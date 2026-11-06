apt-get update && apt-get install -y python3 python3-pip git && \
git clone https://github.com/sahand363/checkspoof.git /opt/checkspoof && \
cd /opt/checkspoof && pip3 install -r requirements.txt && \
python3 app.py



apt-get update && apt-get install -y golang git && \
cd /opt && rm -rf checkspoof && git clone https://github.com/sahand363/checkspoof.git && \
cd /opt/checkspoof && go build -o checkspoof main.go && ./checkspoof
