FROM ros:humble-ros-base

LABEL maintainer="CyberArmor Security Team <security@cyberarmor.ai>"
LABEL description="CyberArmor Protect ROS2 Security Agent"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    python3-yaml \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir requests pyyaml defusedxml

WORKDIR /ros2_ws/src/cyberarmor_ros_agent

COPY . .

WORKDIR /ros2_ws

RUN . /opt/ros/humble/setup.sh && \
    colcon build --packages-select cyberarmor_ros_agent

COPY agents/ros-agent/entrypoint.sh /entrypoint.sh
RUN echo '#!/bin/bash\nset -e\nsource /opt/ros/humble/setup.bash\nsource /ros2_ws/install/setup.bash\nexec "$@"' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /ros2_ws /entrypoint.sh

USER appuser

ENTRYPOINT ["/entrypoint.sh"]
CMD ["ros2", "run", "cyberarmor_ros_agent", "cyberarmor_node"]
