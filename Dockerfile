FROM python:3-alpine
ENV PYTHONUNBUFFERED=1
LABEL name="pinecrypt/firewall" \
      version="rc" \
      maintainer="Pinecrypt Labs <info@pinecrypt.com>"
RUN apk add iptables ip6tables ipset
RUN pip install motor
ADD firewall.py /firewall.py
CMD /firewall.py
