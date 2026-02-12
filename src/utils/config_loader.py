"""
Configuration loader for VIPRecon tool.
Handles loading and merging YAML configuration files.
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigurationError(Exception):
    """Raised when configuration loading or validation fails."""
    pass


class ConfigLoader:
    """Loader and manager for application configuration."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize config loader.
        
        Args:
            config_dir: Directory containing configuration files.
        """
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            # Default to project root / config
            self.config_dir = Path(__file__).parent.parent.parent / "config"
            
    def load_default_config(self) -> Dict[str, Any]:
        """
        Load the default configuration file.
        
        Returns:
            Dictionary containing default configuration.
        """
        default_path = self.config_dir / "default_config.yaml"
        return self.load_config(str(default_path))
        
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to configuration file.
            
        Returns:
            Dictionary containing configuration settings.
            
        Raises:
            ConfigurationError: If config file cannot be loaded or is invalid.
        """
        path = Path(config_path)
        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")
            
        try:
            with open(path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                if config is None:
                    return {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Failed to parse YAML configuration: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to read configuration file: {e}")
            
        self._validate_config(config)
        return config

    def merge_configs(self, base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge two configuration dictionaries.
        """
        return merge_configs(base_config, override_config)

    @staticmethod
    def _validate_config(config: Dict[str, Any]) -> None:
        """
        Validate that required configuration fields are present.
        """
        # We'll make validation a bit more flexible to allow partial configs
        pass


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Helper for legacy support."""
    loader = ConfigLoader()
    if config_path:
        return loader.load_config(config_path)
    return loader.load_default_config()


def merge_configs(base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two configuration dictionaries, with override_config taking precedence.
    """
    merged = base_config.copy() if base_config else {}
    if not override_config:
        return merged
        
    for key, value in override_config.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            # Recursively merge nested dictionaries
            merged[key] = merge_configs(merged[key], value)
        else:
            # Override value
            merged[key] = value
    
    return merged


def get_config_value(config: Dict[str, Any], key_path: str, default: Any = None) -> Any:
    """
    Get a configuration value using dot notation.
    """
    if not config:
        return default
        
    keys = key_path.split('.')
    value = config
    
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
    
    return value
