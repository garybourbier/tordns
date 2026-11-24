include $(TOPDIR)/rules.mk

PKG_NAME:=tordns
PKG_VERSION:=$(if $(TORDNS_VERSION),$(TORDNS_VERSION),0.8.0)
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=TorDNS <tordns@example.invalid>
PKGARCH:=$(ARCH)
# Les binaires Go sont nommés d'après l'architecture de paquet OpenWrt
# (mipsel_24kc, mips_24kc, arm_cortex-a7, aarch64_cortex-a53, x86_64) ; voir
# scripts/ci/client-openwrt.sh. Le binaire arm (GOARM=7) couvre toutes les
# cibles ARMv7, quelle que soit la sous-architecture (a7, a9, a15).
TORDNS_BIN:=$(if $(filter mipsel,$(ARCH)),mipsel_24kc,$(if $(filter mips,$(ARCH)),mips_24kc,$(if $(filter aarch64,$(ARCH)),aarch64_cortex-a53,$(if $(filter arm,$(ARCH)),arm_cortex-a7,$(ARCH)))))

include $(INCLUDE_DIR)/package.mk

define Package/tordns
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TorDNS — relais DNS local vers Tor
  URL:=https://github.com/garybourbier/tordns
  DEPENDS:=+tor +dnsmasq +nftables
endef

define Package/tordns/description
 Relais DNS local TorDNS pour routeur OpenWrt : cache borné, DNSSEC,
 transfert dnsmasq vers 127.0.0.1:5353 et blocage nftables des fuites DNS
 et DoT des clients du LAN. Aucun journal de requêtes.
endef

define Package/tordns/conffiles
/etc/config/tordns
endef

define Package/tordns/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/tordns-client.$(TORDNS_BIN) $(1)/usr/sbin/tordns-client
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config $(1)/etc/tordns
	$(INSTALL_BIN) ./files/etc/init.d/tordns $(1)/etc/init.d/tordns
	$(INSTALL_CONF) ./files/etc/config/tordns $(1)/etc/config/tordns
	$(INSTALL_DATA) ./files/etc/tordns/anti-fuite.nft.template $(1)/etc/tordns/anti-fuite.nft.template
endef

define Build/Compile
endef

$(eval $(call BuildPackage,tordns))
