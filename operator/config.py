"""
Configuration Management Module
Handles configuration loading from multiple sources with priority:
1. Environment variables (highest priority)
2. Config file (config.json)
3. Default values (lowest priority)
"""

import os
import json
import socket

# Default configuration
DEFAULT_CONFIG = {
    "server": {
        "host": "0.0.0.0",
        "port": 8542,
        "inactive_timeout": 300  # 5 minutes in seconds
    },
    "agent": {
        "checkin_interval": 30,  # seconds
        "command_timeout": 30  # seconds
    },
    "operator": {
        "default_server_url": "http://localhost:8542"
    }
}


class Config:
    """Configuration manager with multi-source support"""

    def __init__(self, config_file="config.json"):
        self.config = DEFAULT_CONFIG.copy()
        self.config_file = config_file
        self._load_config()

    def _load_config(self):
        """Load configuration from file if it exists"""
        # Try to load from config file
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    self._merge_config(file_config)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")

        # Override with environment variables
        self._load_from_env()

    def _merge_config(self, new_config):
        """Recursively merge new config into existing config"""
        for key, value in new_config.items():
            if key in self.config and isinstance(self.config[key], dict) and isinstance(value, dict):
                self.config[key].update(value)
            else:
                self.config[key] = value

    def _load_from_env(self):
        """Load configuration from environment variables"""
        # Server configuration
        if os.getenv("OPERATOR_HOST"):
            self.config["server"]["host"] = os.getenv("OPERATOR_HOST")

        if os.getenv("OPERATOR_PORT"):
            try:
                self.config["server"]["port"] = int(os.getenv("OPERATOR_PORT"))
            except ValueError:
                pass

        # Operator URL (full URL override)
        if os.getenv("OPERATOR_URL"):
            self.config["operator"]["default_server_url"] = os.getenv("OPERATOR_URL")

        # Agent configuration
        if os.getenv("CHECKIN_INTERVAL"):
            try:
                self.config["agent"]["checkin_interval"] = int(os.getenv("CHECKIN_INTERVAL"))
            except ValueError:
                pass

    def get(self, *keys):
        """Get configuration value by nested keys"""
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value

    def get_server_url(self):
        """Get the operator server URL"""
        # Check environment variable first
        if os.getenv("OPERATOR_URL"):
            return os.getenv("OPERATOR_URL")

        # Check config
        url = self.get("operator", "default_server_url")
        if url:
            return url

        # Build from host and port
        host = self.get("server", "host")
        port = self.get("server", "port")

        # If host is 0.0.0.0, use localhost for clients
        if host == "0.0.0.0":
            host = "localhost"

        return f"http://{host}:{port}"

    def get_local_ip(self):
        """Get the local IP address of this machine"""
        try:
            # Create a socket to determine the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False


# Global configuration instance
_config = None


def get_config(config_file="config.json"):
    """Get or create the global configuration instance"""
    global _config
    if _config is None:
        # Look for config file in operator directory or current directory
        paths = [
            config_file,
            os.path.join("operator", config_file),
            os.path.join(os.path.dirname(__file__), config_file)
        ]

        for path in paths:
            if os.path.exists(path):
                _config = Config(path)
                return _config

        # No config file found, use defaults
        _config = Config(config_file)

    return _config


def create_default_config(output_path="config.json"):
    """Create a default configuration file"""
    try:
        with open(output_path, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"Default configuration created at: {output_path}")
        return True
    except Exception as e:
        print(f"Error creating config file: {e}")
        return False


if __name__ == "__main__":
    # Create default config file when run directly
    create_default_config()

    # Test configuration loading
    config = get_config()
    print("Configuration loaded:")
    print(f"  Server URL: {config.get_server_url()}")
    print(f"  Server Port: {config.get('server', 'port')}")
    print(f"  Local IP: {config.get_local_ip()}")
