// Détection locale de la plateforme : aucun réseau, aucun cookie, aucun stockage.
// Sans ce script, tous les téléchargements restent visibles et utilisables.
(function () {
  "use strict";
  var plateforme = "autre";
  var ua = navigator.userAgent || "";
  if (/Android/i.test(ua)) {
    plateforme = "android";
  } else if (/iPhone|iPad|iPod/i.test(ua)) {
    plateforme = "ios";
  } else if (/Mac OS X|Macintosh/i.test(ua)) {
    plateforme = "mac";
  } else if (/Windows/i.test(ua)) {
    plateforme = "windows";
  } else if (/Linux|X11/i.test(ua)) {
    plateforme = "linux";
  }
  if (plateforme === "autre") return;
  var cartes = document.querySelectorAll("[data-plateforme]");
  for (var i = 0; i < cartes.length; i++) {
    if (cartes[i].getAttribute("data-plateforme") === plateforme) {
      cartes[i].classList.add("choisi");
    }
  }
})();
