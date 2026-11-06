apt-get update && apt-get install -y wget && \
mkdir -p /opt/checkspoof && cd /opt/checkspoof && \
wget -O checkspoof https://github.com/sahand363/checkspoof/releases/latest/download/checkspoof && \
chmod +x checkspoof && ./checkspoof
