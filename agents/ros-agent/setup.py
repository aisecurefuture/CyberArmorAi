from setuptools import setup, find_packages

package_name = "cyberarmor_ros_agent"

setup(
    name=package_name,
    version="1.0.0",
    packages=find_packages(),
    data_files=[
        ("share/ament_index/resource_index/packages", ["resource/" + package_name]),
        ("share/" + package_name, ["package.xml"]),
    ],
    install_requires=["setuptools", "pyyaml", "requests", "defusedxml"],
    zip_safe=True,
    maintainer="CyberArmor Security Team",
    maintainer_email="security@cyberarmor.ai",
    description="CyberArmor Protect security agent for ROS2 robotic systems",
    license="Proprietary",
    entry_points={
        "console_scripts": [
            "cyberarmor_node = cyberarmor_ros_node:main",
        ],
    },
)
