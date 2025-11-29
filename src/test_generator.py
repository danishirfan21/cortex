"""
Tests for the ConfigGenerator module.

Tests cover:
- Path validation and traversal protection
- Template parameter sanitization
- Atomic file operations
- Backup creation
- Dockerfile generation
- Docker-compose generation
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from generator import (
    ConfigGenerator,
    PathSecurityError,
    TemplateSecurityError,
    GeneratorError,
    setup_logging
)


class TestPathValidation(unittest.TestCase):
    """Tests for path validation and security."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ConfigGenerator(
            allowed_directories=[self.temp_dir]
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_valid_path_in_allowed_directory(self):
        """Test that paths within allowed directories are accepted."""
        output_path = os.path.join(self.temp_dir, 'test.txt')
        result = self.generator._validate_output_path(output_path)
        self.assertEqual(result, Path(output_path).resolve())
    
    def test_path_traversal_rejection(self):
        """Test that path traversal attempts are rejected."""
        # Test various traversal attempts
        dangerous_paths = [
            '../../../etc/passwd',
            '/etc/passwd',
            f'{self.temp_dir}/../../../etc/passwd',
            f'{self.temp_dir}/subdir/../../../etc/hosts',
        ]
        
        for path in dangerous_paths:
            with self.assertRaises(PathSecurityError, msg=f"Should reject: {path}"):
                self.generator._validate_output_path(path)
    
    def test_path_outside_allowed_directories(self):
        """Test that paths outside allowed directories are rejected."""
        with self.assertRaises(PathSecurityError):
            self.generator._validate_output_path('/tmp/not_allowed/file.txt')
    
    def test_shell_metacharacters_rejected(self):
        """Test that paths with shell metacharacters are rejected."""
        dangerous_paths = [
            f'{self.temp_dir}/file;rm -rf /',
            f'{self.temp_dir}/file|cat',
            f'{self.temp_dir}/file`whoami`',
        ]
        
        for path in dangerous_paths:
            with self.assertRaises(PathSecurityError, msg=f"Should reject: {path}"):
                self.generator._validate_output_path(path)
    
    def test_nested_directory_allowed(self):
        """Test that nested directories within allowed paths work."""
        nested_path = os.path.join(self.temp_dir, 'subdir', 'subsubdir', 'file.txt')
        result = self.generator._validate_output_path(nested_path)
        self.assertEqual(result.parent.parent.parent, Path(self.temp_dir).resolve())


class TestParameterValidation(unittest.TestCase):
    """Tests for template parameter sanitization."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ConfigGenerator(
            allowed_directories=[self.temp_dir]
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_valid_string_params(self):
        """Test that valid string parameters are accepted."""
        params = {
            'image': 'python:3.11-slim',
            'port': '8080:80',
            'workdir': '/app'
        }
        result = self.generator._validate_template_params(params)
        self.assertEqual(result, params)
    
    def test_valid_numeric_params(self):
        """Test that numeric parameters are accepted."""
        params = {
            'replicas': 3,
            'memory_limit': 512.5,
            'enabled': True
        }
        result = self.generator._validate_template_params(params)
        self.assertEqual(result, params)
    
    def test_command_injection_rejected(self):
        """Test that command injection attempts are rejected."""
        dangerous_params = [
            {'image': 'python; rm -rf /'},
            {'port': '80|cat /etc/passwd'},
            {'env': 'VAR=value`whoami`'},
            {'cmd': 'echo $(id)'},
        ]
        
        for params in dangerous_params:
            with self.assertRaises(TemplateSecurityError, msg=f"Should reject: {params}"):
                self.generator._validate_template_params(params)
    
    def test_path_traversal_in_params_rejected(self):
        """Test that path traversal in parameters is rejected."""
        with self.assertRaises(TemplateSecurityError):
            self.generator._validate_template_params({
                'volume': '../../../etc/passwd:/etc/passwd'
            })
    
    def test_nested_dict_validation(self):
        """Test that nested dictionaries are validated."""
        params = {
            'environment': {
                'DEBUG': 'true',
                'PORT': '8080'
            }
        }
        result = self.generator._validate_template_params(params)
        self.assertEqual(result, params)
    
    def test_list_params_validation(self):
        """Test that list parameters are validated."""
        params = {
            'packages': ['python3', 'git', 'curl']
        }
        result = self.generator._validate_template_params(params)
        self.assertEqual(result, params)
    
    def test_invalid_key_rejected(self):
        """Test that invalid parameter keys are rejected."""
        with self.assertRaises(TemplateSecurityError):
            self.generator._validate_template_params({
                'key;rm -rf /': 'value'
            })


class TestAtomicOperations(unittest.TestCase):
    """Tests for atomic file operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ConfigGenerator(
            allowed_directories=[self.temp_dir]
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_atomic_write_creates_file(self):
        """Test that atomic write creates a file."""
        file_path = Path(self.temp_dir) / 'test.txt'
        self.generator._atomic_write(file_path, 'test content')
        
        self.assertTrue(file_path.exists())
        self.assertEqual(file_path.read_text(), 'test content')
    
    def test_atomic_write_creates_parent_dirs(self):
        """Test that atomic write creates parent directories."""
        file_path = Path(self.temp_dir) / 'subdir' / 'subsubdir' / 'test.txt'
        self.generator._atomic_write(file_path, 'test content')
        
        self.assertTrue(file_path.exists())
        self.assertEqual(file_path.read_text(), 'test content')
    
    def test_atomic_write_overwrites_existing(self):
        """Test that atomic write overwrites existing files."""
        file_path = Path(self.temp_dir) / 'test.txt'
        file_path.write_text('original content')
        
        self.generator._atomic_write(file_path, 'new content')
        
        self.assertEqual(file_path.read_text(), 'new content')
    
    def test_backup_creation(self):
        """Test that backups are created for existing files."""
        file_path = Path(self.temp_dir) / 'test.txt'
        file_path.write_text('original content')
        
        backup_path = self.generator._create_backup(file_path)
        
        self.assertIsNotNone(backup_path)
        self.assertTrue(backup_path.exists())
        self.assertEqual(backup_path.read_text(), 'original content')
        self.assertIn('.backup_', str(backup_path))
    
    def test_no_backup_for_nonexistent_file(self):
        """Test that no backup is created for non-existent files."""
        file_path = Path(self.temp_dir) / 'nonexistent.txt'
        backup_path = self.generator._create_backup(file_path)
        self.assertIsNone(backup_path)


class TestDockerfileGeneration(unittest.TestCase):
    """Tests for Dockerfile generation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ConfigGenerator(
            allowed_directories=[self.temp_dir]
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_basic_dockerfile_generation(self):
        """Test basic Dockerfile generation."""
        output_path = os.path.join(self.temp_dir, 'Dockerfile')
        
        result = self.generator.generate_dockerfile(
            output_path=output_path,
            base_image='python:3.11',
            create_backup=False
        )
        
        self.assertEqual(result, output_path)
        content = Path(output_path).read_text()
        self.assertIn('FROM python:3.11', content)
        self.assertIn('WORKDIR /app', content)
    
    def test_dockerfile_with_packages(self):
        """Test Dockerfile generation with packages."""
        output_path = os.path.join(self.temp_dir, 'Dockerfile')
        
        self.generator.generate_dockerfile(
            output_path=output_path,
            packages=['git', 'curl'],
            create_backup=False
        )
        
        content = Path(output_path).read_text()
        self.assertIn('apt-get install', content)
        self.assertIn('git curl', content)
    
    def test_dockerfile_custom_workdir(self):
        """Test Dockerfile with custom working directory."""
        output_path = os.path.join(self.temp_dir, 'Dockerfile')
        
        self.generator.generate_dockerfile(
            output_path=output_path,
            workdir='/opt/myapp',
            create_backup=False
        )
        
        content = Path(output_path).read_text()
        self.assertIn('WORKDIR /opt/myapp', content)
    
    def test_dockerfile_path_traversal_blocked(self):
        """Test that path traversal in Dockerfile output is blocked."""
        with self.assertRaises(PathSecurityError):
            self.generator.generate_dockerfile(
                output_path='../../../etc/Dockerfile',
                create_backup=False
            )


class TestDockerComposeGeneration(unittest.TestCase):
    """Tests for docker-compose.yml generation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ConfigGenerator(
            allowed_directories=[self.temp_dir]
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_basic_compose_generation(self):
        """Test basic docker-compose.yml generation."""
        output_path = os.path.join(self.temp_dir, 'docker-compose.yml')
        
        result = self.generator.generate_docker_compose(
            output_path=output_path,
            service_name='web',
            image='nginx:latest',
            create_backup=False
        )
        
        self.assertEqual(result, output_path)
        content = Path(output_path).read_text()
        self.assertIn("version: '3.8'", content)
        self.assertIn('web:', content)
        self.assertIn('image: nginx:latest', content)
    
    def test_compose_with_build(self):
        """Test docker-compose.yml with build context."""
        output_path = os.path.join(self.temp_dir, 'docker-compose.yml')
        
        self.generator.generate_docker_compose(
            output_path=output_path,
            build_context='.',
            create_backup=False
        )
        
        content = Path(output_path).read_text()
        self.assertIn('build: .', content)
        self.assertNotIn('image:', content)
    
    def test_compose_image_takes_precedence_over_build(self):
        """Test that image takes precedence over build to avoid conflicts."""
        output_path = os.path.join(self.temp_dir, 'docker-compose.yml')
        
        self.generator.generate_docker_compose(
            output_path=output_path,
            image='myimage:latest',
            build_context='.',  # Should be ignored
            create_backup=False
        )
        
        content = Path(output_path).read_text()
        self.assertIn('image: myimage:latest', content)
        self.assertNotIn('build:', content)
    
    def test_compose_with_ports(self):
        """Test docker-compose.yml with port mappings."""
        output_path = os.path.join(self.temp_dir, 'docker-compose.yml')
        
        self.generator.generate_docker_compose(
            output_path=output_path,
            image='nginx',
            ports=['8080:80', '443:443'],
            create_backup=False
        )
        
        content = Path(output_path).read_text()
        self.assertIn('ports:', content)
        self.assertIn('8080:80', content)
        self.assertIn('443:443', content)
    
    def test_compose_with_environment(self):
        """Test docker-compose.yml with environment variables."""
        output_path = os.path.join(self.temp_dir, 'docker-compose.yml')
        
        self.generator.generate_docker_compose(
            output_path=output_path,
            image='myapp',
            environment={'DEBUG': 'true', 'PORT': '8080'},
            create_backup=False
        )
        
        content = Path(output_path).read_text()
        self.assertIn('environment:', content)
        self.assertIn('DEBUG: "true"', content)
        self.assertIn('PORT: "8080"', content)
    
    def test_compose_command_injection_blocked(self):
        """Test that command injection in compose params is blocked."""
        output_path = os.path.join(self.temp_dir, 'docker-compose.yml')
        
        with self.assertRaises(TemplateSecurityError):
            self.generator.generate_docker_compose(
                output_path=output_path,
                image='nginx; rm -rf /',
                create_backup=False
            )


class TestTemplateGeneration(unittest.TestCase):
    """Tests for template-based generation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.templates_dir = tempfile.mkdtemp()
        self.generator = ConfigGenerator(
            allowed_directories=[self.temp_dir],
            templates_dir=self.templates_dir
        )
        
        # Create a test template
        template_path = Path(self.templates_dir) / 'test.template'
        template_path.write_text('Hello ${name}! Port: ${port}')
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.templates_dir, ignore_errors=True)
    
    def test_template_generation(self):
        """Test template-based generation."""
        output_path = os.path.join(self.temp_dir, 'output.txt')
        
        result = self.generator.generate_from_template(
            template_name='test.template',
            output_path=output_path,
            params={'name': 'World', 'port': '8080'},
            create_backup=False
        )
        
        self.assertEqual(result, output_path)
        content = Path(output_path).read_text()
        self.assertIn('Hello World!', content)
        self.assertIn('Port: 8080', content)
    
    def test_template_path_traversal_blocked(self):
        """Test that path traversal in template name is blocked."""
        output_path = os.path.join(self.temp_dir, 'output.txt')
        
        with self.assertRaises(PathSecurityError):
            self.generator.generate_from_template(
                template_name='../../../etc/passwd',
                output_path=output_path,
                params={},
                create_backup=False
            )
    
    def test_template_injection_blocked(self):
        """Test that template injection is blocked."""
        output_path = os.path.join(self.temp_dir, 'output.txt')
        
        with self.assertRaises(TemplateSecurityError):
            self.generator.generate_from_template(
                template_name='test.template',
                output_path=output_path,
                params={'name': 'test; rm -rf /'},
                create_backup=False
            )
    
    def test_nonexistent_template(self):
        """Test error handling for non-existent templates."""
        output_path = os.path.join(self.temp_dir, 'output.txt')
        
        with self.assertRaises(GeneratorError):
            self.generator.generate_from_template(
                template_name='nonexistent.template',
                output_path=output_path,
                params={},
                create_backup=False
            )


class TestLogging(unittest.TestCase):
    """Tests for logging configuration."""
    
    def test_setup_logging(self):
        """Test logging setup."""
        # Should not raise
        setup_logging('INFO')
        setup_logging('DEBUG')
        setup_logging('WARNING')


class TestInitialization(unittest.TestCase):
    """Tests for ConfigGenerator initialization."""
    
    def test_default_initialization(self):
        """Test default initialization."""
        generator = ConfigGenerator()
        self.assertIsNotNone(generator.allowed_directories)
        self.assertGreater(len(generator.allowed_directories), 0)
    
    def test_custom_allowed_directories(self):
        """Test initialization with custom allowed directories."""
        temp_dir = tempfile.mkdtemp()
        try:
            generator = ConfigGenerator(allowed_directories=[temp_dir])
            self.assertEqual(len(generator.allowed_directories), 1)
            self.assertEqual(generator.allowed_directories[0], Path(temp_dir).resolve())
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
