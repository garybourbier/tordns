# TorDNS — onionbalance v3 pour le contrôleur (Mission 9).
# Version épinglée : une mise à jour silencieuse changerait le format du
# descripteur maître et la façon de le publier.
FROM python:3.12-slim

RUN pip install --no-cache-dir onionbalance==0.2.4

# Le processus tourne sans privilège : l'uid/gid est fourni par le compose
# (100:101 en installation normale, celui de l'appelant dans les tests).
WORKDIR /donnees

ENTRYPOINT ["onionbalance"]
