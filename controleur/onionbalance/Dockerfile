# TorDNS — onionbalance v3 pour le contrôleur (Mission 9).
# Version épinglée : une mise à jour silencieuse changerait le format du
# descripteur maître et la façon de le publier.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

RUN pip install --no-cache-dir onionbalance==0.2.4

# Le processus tourne sans privilège : l'uid/gid est fourni par le compose
# (100:101 en installation normale, celui de l'appelant dans les tests).
WORKDIR /donnees

ENTRYPOINT ["onionbalance"]
