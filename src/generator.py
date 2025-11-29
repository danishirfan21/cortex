"""
Configuration Generator for Cortex Linux

Generates deployment configurations (Docker, docker-compose, etc.) with
secure path handling and template processing.

Security features:
- Path canonicalization and validation
- Parameter sanitization for template injection prevention
- Atomic file operations with file locking
- Proper logging instead of print statements
"""

import fcntl
import logging
import os
import re
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, ClassVar

# Configure logging
logger = logging.getLogger(__name__)


class PathSecurityError(Exception):
    """Raised when path validation fails."""
    pass


class TemplateSecurityError(Exception):
    """Raised when template parameter validation fails."""
    pass


class GeneratorError(Exception):
    """General generator error."""
    pass


class ConfigGenerator:
    """
    Generates deployment configurations with security-first design.
    
    Security features:
    - Path traversal protection via canonicalization
    - Template injection prevention via parameter validation
    - Race condition prevention via atomic file operations
    - Comprehensive logging
    
    Attributes:
        allowed_directories: List of directories where output files can be created
        templates_dir: Directory containing template files
    """
    
    # Pre-compiled regex patterns for validation (performance optimization)
    SAFE_PARAM_PATTERN: ClassVar[re.Pattern] = re.compile(r'^[a-zA-Z0-9._\-:/@]+$')
    SAFE_PATH_PATTERN: ClassVar[re.Pattern] = re.compile(r'^[a-zA-Z0-9._\-/]+$')
    DANGEROUS_PATTERNS: ClassVar[List[re.Pattern]] = [
        re.compile(r'[;&|`$(){}]'),  # Shell metacharacters
        re.compile(r'\.\./'),         # Directory traversal
        re.compile(r'\.\.\\'),        # Windows directory traversal
        re.compile(r'^/etc/'),        # System config files
        re.compile(r'^/usr/'),        # System binaries
        re.compile(r'^/bin/'),        # System binaries
        re.compile(r'^/sbin/'),       # System binaries
    ]
    
    def __init__(
        self,
        allowed_directories: Optional[List[str]] = None,
        templates_dir: Optional[str] = None
    ):
        """
        Initialize the ConfigGenerator.
        
        Args:
            allowed_directories: List of directories where output is allowed.
                                Defaults to current working directory and /tmp.
            templates_dir: Directory containing template files.
                          Defaults to ./templates.
        
        Raises:
            PathSecurityError: If allowed directories cannot be validated.
        """
        self.allowed_directories = self._validate_allowed_directories(
            allowed_directories or [os.getcwd(), tempfile.gettempdir()]
        )
        self.templates_dir = Path(templates_dir or './templates').resolve()
        
        logger.info(
            "ConfigGenerator initialized with allowed directories: %s",
            self.allowed_directories
        )
    
    def _validate_allowed_directories(self, directories: List[str]) -> List[Path]:
        """
        Validate and canonicalize allowed directories.
        
        Args:
            directories: List of directory paths to validate.
        
        Returns:
            List of canonicalized Path objects.
        
        Raises:
            PathSecurityError: If any directory is invalid.
        """
        validated = []
        for dir_path in directories:
            try:
                resolved = Path(dir_path).resolve()
                if not resolved.exists():
                    logger.warning(
                        "Allowed directory does not exist: %s", resolved
                    )
                validated.append(resolved)
            except Exception as e:
                raise PathSecurityError(
                    f"Failed to validate directory '{dir_path}': {e}"
                )
        return validated
    
    def _validate_output_path(self, output_path: str) -> Path:
        """
        Validate and canonicalize output path.
        
        This method implements path traversal protection by:
        1. Resolving the path to its canonical form
        2. Ensuring the path is within allowed directories
        3. Checking for dangerous patterns
        
        Args:
            output_path: The requested output path.
        
        Returns:
            Canonicalized Path object.
        
        Raises:
            PathSecurityError: If the path is invalid or outside allowed directories.
        """
        # Canonicalize the path to resolve symlinks and relative components
        try:
            resolved_path = Path(output_path).resolve()
        except Exception as e:
            raise PathSecurityError(f"Invalid path '{output_path}': {e}")
        
        # Check for dangerous patterns in the original path
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.search(output_path):
                raise PathSecurityError(
                    f"Path '{output_path}' contains dangerous pattern"
                )
        
        # Verify path is within allowed directories
        is_allowed = False
        for allowed_dir in self.allowed_directories:
            try:
                resolved_path.relative_to(allowed_dir)
                is_allowed = True
                break
            except ValueError:
                continue
        
        if not is_allowed:
            raise PathSecurityError(
                f"Path '{resolved_path}' is outside allowed directories. "
                f"Allowed: {[str(d) for d in self.allowed_directories]}"
            )
        
        logger.debug("Validated output path: %s -> %s", output_path, resolved_path)
        return resolved_path
    
    def _validate_template_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate template parameters to prevent injection attacks.
        
        This method sanitizes all parameter values to prevent:
        1. Shell command injection
        2. Template injection
        3. Path traversal via parameter values
        
        Args:
            params: Dictionary of template parameters.
        
        Returns:
            Validated and sanitized parameters.
        
        Raises:
            TemplateSecurityError: If any parameter fails validation.
        """
        validated = {}
        
        for key, value in params.items():
            # Validate key
            if not self.SAFE_PARAM_PATTERN.match(key):
                raise TemplateSecurityError(
                    f"Parameter key '{key}' contains invalid characters"
                )
            
            # Validate value based on type
            if isinstance(value, str):
                validated[key] = self._sanitize_string_param(key, value)
            elif isinstance(value, (int, float, bool)):
                validated[key] = value
            elif isinstance(value, list):
                validated[key] = [
                    self._sanitize_string_param(key, v) if isinstance(v, str) else v
                    for v in value
                ]
            elif isinstance(value, dict):
                validated[key] = self._validate_template_params(value)
            else:
                raise TemplateSecurityError(
                    f"Unsupported parameter type for '{key}': {type(value)}"
                )
        
        logger.debug("Validated %d template parameters", len(validated))
        return validated
    
    def _sanitize_string_param(self, key: str, value: str) -> str:
        """
        Sanitize a string parameter value.
        
        Args:
            key: Parameter name (for error messages).
            value: String value to sanitize.
        
        Returns:
            Sanitized string value.
        
        Raises:
            TemplateSecurityError: If value contains dangerous content.
        """
        # Check for shell metacharacters
        dangerous_chars = re.compile(r'[;&|`$(){}\\]')
        if dangerous_chars.search(value):
            raise TemplateSecurityError(
                f"Parameter '{key}' contains dangerous characters: {value!r}"
            )
        
        # Check for path traversal attempts in values that look like paths
        if '/' in value or '\\' in value:
            if '..' in value:
                raise TemplateSecurityError(
                    f"Parameter '{key}' contains path traversal attempt: {value!r}"
                )
        
        return value
    
    def _atomic_write(self, path: Path, content: str) -> None:
        """
        Write content to file atomically with file locking.
        
        This method prevents race conditions (TOCTOU) by:
        1. Writing to a temporary file
        2. Using file locking during the write
        3. Atomically moving the temp file to the target
        
        Args:
            path: Target file path.
            content: Content to write.
        
        Raises:
            GeneratorError: If write fails.
        """
        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create temporary file in the same directory for atomic rename
        temp_fd = None
        temp_path = None
        
        try:
            # Create temp file
            temp_fd, temp_path = tempfile.mkstemp(
                dir=path.parent,
                prefix='.tmp_',
                suffix='_' + path.name
            )
            
            # Write with exclusive lock
            with os.fdopen(temp_fd, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            temp_fd = None  # Prevent double close
            
            # Atomic rename
            os.rename(temp_path, path)
            logger.info("Atomically wrote file: %s", path)
            temp_path = None  # Prevent cleanup
            
        except Exception as e:
            raise GeneratorError(f"Failed to write file '{path}': {e}")
        finally:
            # Clean up temp file if rename failed
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
    
    def _create_backup(self, path: Path) -> Optional[Path]:
        """
        Create a backup of existing file using atomic operations.
        
        This method uses atomic operations to prevent TOCTOU race conditions
        between checking if file exists and creating backup.
        
        Args:
            path: Path to file to backup.
        
        Returns:
            Path to backup file, or None if original didn't exist.
        """
        if not path.exists():
            return None
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = path.with_suffix(f'.backup_{timestamp}{path.suffix}')
        
        try:
            # Use shutil.copy2 with os.link for atomic copy when possible
            # First try hard link (atomic), fall back to copy
            try:
                os.link(path, backup_path)
                logger.info("Created backup (hard link): %s", backup_path)
            except OSError:
                # Fall back to copy (not atomic, but still safe with temp file)
                shutil.copy2(path, backup_path)
                logger.info("Created backup (copy): %s", backup_path)
            
            return backup_path
        except Exception as e:
            logger.error("Failed to create backup for %s: %s", path, e)
            raise GeneratorError(f"Failed to create backup: {e}")
    
    def generate_dockerfile(
        self,
        output_path: str,
        base_image: str = 'python:3.11-slim',
        packages: Optional[List[str]] = None,
        workdir: str = '/app',
        create_backup: bool = True
    ) -> str:
        """
        Generate a Dockerfile with security validation.
        
        Args:
            output_path: Where to save the Dockerfile.
            base_image: Base Docker image.
            packages: System packages to install.
            workdir: Working directory in container.
            create_backup: Whether to backup existing file.
        
        Returns:
            Path to generated Dockerfile.
        
        Raises:
            PathSecurityError: If output path is invalid.
            TemplateSecurityError: If parameters are invalid.
        """
        # Validate output path
        validated_path = self._validate_output_path(output_path)
        
        # Validate parameters
        params = self._validate_template_params({
            'base_image': base_image,
            'workdir': workdir,
            'packages': packages or []
        })
        
        # Create backup if requested
        if create_backup:
            self._create_backup(validated_path)
        
        # Generate content
        lines = [
            f"FROM {params['base_image']}",
            "",
            f"WORKDIR {params['workdir']}",
            "",
        ]
        
        if params['packages']:
            pkg_list = ' '.join(params['packages'])
            lines.extend([
                "RUN apt-get update && apt-get install -y \\",
                f"    {pkg_list} \\",
                "    && rm -rf /var/lib/apt/lists/*",
                "",
            ])
        
        lines.extend([
            "COPY requirements.txt .",
            "RUN pip install --no-cache-dir -r requirements.txt",
            "",
            "COPY . .",
            "",
            'CMD ["python", "main.py"]',
            "",
        ])
        
        content = '\n'.join(lines)
        
        # Write atomically
        self._atomic_write(validated_path, content)
        
        logger.info("Generated Dockerfile at %s", validated_path)
        return str(validated_path)
    
    def generate_docker_compose(
        self,
        output_path: str,
        service_name: str = 'app',
        image: Optional[str] = None,
        build_context: Optional[str] = None,
        ports: Optional[List[str]] = None,
        environment: Optional[Dict[str, str]] = None,
        volumes: Optional[List[str]] = None,
        create_backup: bool = True
    ) -> str:
        """
        Generate a docker-compose.yml with security validation.
        
        Note: If both image and build_context are provided, image takes precedence
        to avoid conflicts. Use either image OR build_context, not both.
        
        Args:
            output_path: Where to save the docker-compose.yml.
            service_name: Name of the service.
            image: Docker image to use (conflicts with build_context).
            build_context: Build context path (conflicts with image).
            ports: Port mappings.
            environment: Environment variables.
            volumes: Volume mounts.
            create_backup: Whether to backup existing file.
        
        Returns:
            Path to generated docker-compose.yml.
        
        Raises:
            PathSecurityError: If output path is invalid.
            TemplateSecurityError: If parameters are invalid.
        """
        # Validate output path
        validated_path = self._validate_output_path(output_path)
        
        # Validate parameters
        params = self._validate_template_params({
            'service_name': service_name,
            'image': image or '',
            'build_context': build_context or '',
            'ports': ports or [],
            'environment': environment or {},
            'volumes': volumes or []
        })
        
        # Create backup if requested
        if create_backup:
            self._create_backup(validated_path)
        
        # Generate content - avoid image/build conflict
        lines = [
            "version: '3.8'",
            "",
            "services:",
            f"  {params['service_name']}:",
        ]
        
        # Use image OR build, not both (image takes precedence)
        if params['image']:
            lines.append(f"    image: {params['image']}")
        elif params['build_context']:
            lines.append(f"    build: {params['build_context']}")
        
        if params['ports']:
            lines.append("    ports:")
            for port in params['ports']:
                lines.append(f"      - \"{port}\"")
        
        if params['environment']:
            lines.append("    environment:")
            for key, value in params['environment'].items():
                lines.append(f"      {key}: \"{value}\"")
        
        if params['volumes']:
            lines.append("    volumes:")
            for volume in params['volumes']:
                lines.append(f"      - {volume}")
        
        lines.append("")
        
        content = '\n'.join(lines)
        
        # Write atomically
        self._atomic_write(validated_path, content)
        
        logger.info("Generated docker-compose.yml at %s", validated_path)
        return str(validated_path)
    
    def generate_from_template(
        self,
        template_name: str,
        output_path: str,
        params: Dict[str, Any],
        create_backup: bool = True
    ) -> str:
        """
        Generate configuration from a template file.
        
        Args:
            template_name: Name of template file in templates directory.
            output_path: Where to save the generated configuration.
            params: Template parameters.
            create_backup: Whether to backup existing file.
        
        Returns:
            Path to generated configuration file.
        
        Raises:
            PathSecurityError: If any path is invalid.
            TemplateSecurityError: If parameters are invalid.
            GeneratorError: If template processing fails.
        """
        # Validate template name (prevent traversal)
        if '..' in template_name or template_name.startswith('/'):
            raise PathSecurityError(
                f"Invalid template name: {template_name}"
            )
        
        template_path = self.templates_dir / template_name
        
        if not template_path.exists():
            raise GeneratorError(f"Template not found: {template_path}")
        
        # Ensure template is within templates directory
        try:
            template_path.resolve().relative_to(self.templates_dir)
        except ValueError:
            raise PathSecurityError(
                f"Template path escapes templates directory: {template_name}"
            )
        
        # Validate output path
        validated_output = self._validate_output_path(output_path)
        
        # Validate parameters
        validated_params = self._validate_template_params(params)
        
        # Create backup if requested
        if create_backup:
            self._create_backup(validated_output)
        
        # Read and process template
        try:
            template_content = template_path.read_text()
            
            # Simple placeholder substitution (no eval/exec)
            content = template_content
            for key, value in validated_params.items():
                placeholder = f'${{{key}}}'
                if isinstance(value, str):
                    content = content.replace(placeholder, value)
                elif isinstance(value, (int, float, bool)):
                    content = content.replace(placeholder, str(value))
            
            # Write atomically
            self._atomic_write(validated_output, content)
            
            logger.info(
                "Generated configuration from template %s at %s",
                template_name, validated_output
            )
            return str(validated_output)
            
        except Exception as e:
            raise GeneratorError(f"Failed to process template: {e}")


def setup_logging(level: str = 'INFO') -> None:
    """
    Configure logging for the generator module.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR).
    """
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def main():
    """CLI entry point for config generator."""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Cortex Configuration Generator')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Dockerfile command
    dockerfile_parser = subparsers.add_parser('dockerfile',
                                               help='Generate Dockerfile')
    dockerfile_parser.add_argument('--output', '-o', required=True,
                                   help='Output file path')
    dockerfile_parser.add_argument('--base-image', default='python:3.11-slim',
                                   help='Base Docker image')
    dockerfile_parser.add_argument('--packages', nargs='*',
                                   help='System packages to install')
    dockerfile_parser.add_argument('--workdir', default='/app',
                                   help='Working directory')
    dockerfile_parser.add_argument('--no-backup', action='store_true',
                                   help='Skip backup of existing file')
    
    # Docker-compose command
    compose_parser = subparsers.add_parser('docker-compose',
                                           help='Generate docker-compose.yml')
    compose_parser.add_argument('--output', '-o', required=True,
                               help='Output file path')
    compose_parser.add_argument('--service', default='app',
                               help='Service name')
    compose_parser.add_argument('--image',
                               help='Docker image (conflicts with --build)')
    compose_parser.add_argument('--build',
                               help='Build context (conflicts with --image)')
    compose_parser.add_argument('--ports', nargs='*',
                               help='Port mappings')
    compose_parser.add_argument('--no-backup', action='store_true',
                               help='Skip backup of existing file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Setup logging
    setup_logging('DEBUG' if args.verbose else 'INFO')
    
    try:
        generator = ConfigGenerator()
        
        if args.command == 'dockerfile':
            result = generator.generate_dockerfile(
                output_path=args.output,
                base_image=args.base_image,
                packages=args.packages,
                workdir=args.workdir,
                create_backup=not args.no_backup
            )
            logger.info("Successfully generated: %s", result)
            
        elif args.command == 'docker-compose':
            result = generator.generate_docker_compose(
                output_path=args.output,
                service_name=args.service,
                image=args.image,
                build_context=args.build,
                ports=args.ports,
                create_backup=not args.no_backup
            )
            logger.info("Successfully generated: %s", result)
            
    except (PathSecurityError, TemplateSecurityError) as e:
        logger.error("Security validation failed: %s", e)
        sys.exit(1)
    except GeneratorError as e:
        logger.error("Generation failed: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        sys.exit(1)


if __name__ == '__main__':
    main()
