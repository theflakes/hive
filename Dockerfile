# Use the official Ubuntu Python image
FROM ubuntu/python:latest

# Install necessary packages
RUN apt-get update && \
    apt-get install -y python3 python3-pip systemd python-nmap

# Install Python packages
RUN pip3 install python-nmap netifaces ipaddress ipcalc

# Create the /opt/hive directory
RUN mkdir -p /opt/hive
RUN mkdir -p /opt/hive/config/listeners
RUN mkdir -p /opt/hive/logs

# Copy the Python script and other files to /opt/hive
COPY hive.py /opt/hive/
COPY ./config/config.json /opt/hive/config/config.json
COPY ./config/listeners/*.json /opt/hive/config/listeners/

# Create a systemd service file
RUN echo "[Unit]\n\
Description=My Python Service\n\
After=network.target\n\
\n\
[Service]\n\
ExecStart=/usr/bin/python3 /opt/hive/hive.py\n\
WorkingDirectory=/opt/hive\n\
StandardOutput=inherit\n\
StandardError=inherit\n\
Restart=always\n\
User=root\n\
Group=root\n\
\n\
[Install]\n\
WantedBy=multi-user.target" > /etc/systemd/system/hive.service

# Enable the systemd service
RUN systemctl enable hive.service
RUN systemctl enable hive.service

# Start systemd
CMD ["/sbin/init"]
