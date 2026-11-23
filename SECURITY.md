# Sécurité de TorDNS

## Signaler une faille

Utilisez le **signalement privé de GitHub** :
<https://github.com/garybourbier/tordns/security/advisories/new>.

N’ouvrez pas d’issue publique et n’envoyez pas de secret, de clé privée ni
d’adresse `.onion` réelle. Le formulaire GitHub permet un échange privé avec
les mainteneurs, sans publier votre adresse personnelle.

Décrivez si possible : la version, la plateforme, les étapes de reproduction,
l’impact et une preuve minimale. Ne joignez pas de données personnelles ni de
clé de production.

## Périmètre

Sont concernés : le client Linux/macOS/Windows/Android, le relais DNS, la
vérification DNSSEC, le cache, le manifeste signé et son application, les
images du nœud, l’installeur et les workflows de publication.

Les limites connues sont documentées sur le site et dans le journal des
missions : un bénévole peut journaliser les requêtes reçues par son nœud, Tor
ne protège pas contre un nœud malveillant, et DNSSEC ne couvre pas les zones
qui ne le publient pas. Ces points ne sont pas des vulnérabilités à eux seuls.

## Divulgation

Nous accuserons réception dès que possible, travaillerons à un correctif et
coordonnerons la publication avec vous. Aucune récompense financière n’est
promise. Merci de laisser un délai raisonnable avant toute divulgation
publique.
