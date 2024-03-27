#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
import datetime
import logging
import socket
import json
import os

from argparse import ArgumentParser
import time

from scapy.automaton import ATMT
from scapy.layers.tls.automaton_cli import TLSClientAutomaton
from scapy.layers.tls.handshake import TLSClientHello, TLS13ClientHello, TLSServerHello, TLSNewSessionTicket
from scapy.layers.tls.basefields import _tls_version, _tls_version_options
from scapy.layers.tls.crypto.suites import _tls_cipher_suites
from scapy.layers.tls.extensions import TLS_Ext_ClientCertType, TLS_Ext_ClientCertURL, \
                                        TLS_Ext_ClientAuthz, TLS_Ext_EarlyDataIndication, \
                                        TLS_Ext_EncryptThenMAC, TLS_Ext_ExtendedMasterSecret, \
                                        TLS_Ext_Heartbeat, TLS_Ext_MaxFragLen, TLS_Ext_RenegotiationInfo, \
                                        TLS_Ext_ServerAuthz, TLS_Ext_SupportedPointFormat, TLS_Ext_TruncatedHMAC, \
                                        TLS_Ext_SignatureAlgorithms, TLS_Ext_ServerName, ServerName, \
                                        TLS_Ext_SupportedGroups, TLS_Ext_CSR, _tls_ext, OCSPStatusRequest, \
                                        TLS_Ext_ServerCertType, TLS_Ext_SupportedVersion_CH, \
                                        TLS_Ext_PSKKeyExchangeModes, conf, TLS_Ext_ALPN, TLS_Ext_SessionTicket, \
                                        TLS_Ext_RecordSizeLimit, ProtocolName, TLS_Ext_TrustedCAInd, \
                                        TLS_Ext_UserMapping, TLS_Ext_Padding, TLS_Ext_Cookie, TLS_Ext_Unknown
from scapy.layers.tls.crypto.groups import _tls_named_curves
from scapy.layers.tls.cert import PubKeyRSA, PubKeyECDSA, Cert
from scapy.layers import x509
from scapy.layers.tls.keyexchange_tls13 import TLS_Ext_KeyShare_CH, \
    KeyShareEntry, PSKIdentity, PSKBinderEntry, \
    TLS_Ext_PreSharedKey_CH
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from scapy.layers.tls.crypto.suites import _tls_cipher_suites, \
    _tls_cipher_suites_cls

from rich import print
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

import jsonpickle

from bs4 import BeautifulSoup
from itertools import chain

class TLSCheckerAutomaton(TLSClientAutomaton):
    """
    Represents a client automaton.
    
    This class extends the `TLSClientAutomaton` class and provides additional functionality. (see `scapy.layers.tls.automaton_cli.TLSClientAutomaton` for more details)

    Methods:
    - get_server_parameters: Retrieves the server parameters after the handshake is completed.
    """
    @ATMT.state()
    def PREPARE_CLIENTFLIGHT1(self):
        self.add_record()

    @ATMT.condition(PREPARE_CLIENTFLIGHT1)
    def should_add_ClientHello(self):
        if self.client_hello:
            p = self.client_hello
        else:
            p = TLSClientHello()
            ext = []
            # Add TLS_Ext_SignatureAlgorithms for TLS 1.2 ClientHello
            if self.cur_session.advertised_tls_version == 0x0303:
                ext += [TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsa"])]
            # Add TLS_Ext_ServerName
            if self.server_name:
                ext += TLS_Ext_ServerName(
                    servernames=[ServerName(servername=self.server_name)]
                )
            p.ext = ext
        self.add_msg(p)
        raise self.ADDED_CLIENTHELLO()

    @ATMT.state()
    def TLS13_START(self):
        pass

    @ATMT.condition(TLS13_START)
    def tls13_should_add_ClientHello(self):
        # we have to use the legacy, plaintext TLS record here
        supported_groups = ["secp256r1", "secp384r1", "x448"]
        if conf.crypto_valid_advanced:
            supported_groups.append("x25519")
        self.add_record(is_tls13=False)
        if self.client_hello:
            p = self.client_hello
        else:
            if self.ciphersuite is None:
                c = 0x1301
            else:
                c = self.ciphersuite
            p = TLS13ClientHello(ciphers=c)

        ext = p.ext if p.ext else []
        ext += TLS_Ext_SupportedVersion_CH(versions=["TLS 1.3"])

        s = self.cur_session

        if s.tls13_psk_secret:
            # Check if DHE is need (both for out of band and resumption PSK)
            if self.tls13_psk_mode == "psk_dhe_ke":
                ext += TLS_Ext_PSKKeyExchangeModes(kxmodes="psk_dhe_ke")
                ext += TLS_Ext_SupportedGroups(groups=supported_groups)
                ext += TLS_Ext_KeyShare_CH(
                    client_shares=[KeyShareEntry(group=self.curve)]
                )
            else:
                ext += TLS_Ext_PSKKeyExchangeModes(kxmodes="psk_ke")

            # RFC844, section 4.2.11.
            # "The "pre_shared_key" extension MUST be the last extension
            # in the ClientHello "
            # Compute the pre_shared_key extension for resumption PSK
            if s.client_session_ticket:
                cs_cls = _tls_cipher_suites_cls[s.tls13_ticket_ciphersuite]  # noqa: E501
                hkdf = TLS13_HKDF(cs_cls.hash_alg.name.lower())
                hash_len = hkdf.hash.digest_size
                # We compute the client's view of the age of the ticket (ie
                # the time since the receipt of the ticket) in ms
                agems = int((time.time() - s.client_ticket_age) * 1000)
                # Then we compute the obfuscated version of the ticket age
                # by adding the "ticket_age_add" value included in the
                # ticket (modulo 2^32)
                obfuscated_age = ((agems + s.client_session_ticket_age_add) &
                                0xffffffff)

                psk_id = PSKIdentity(identity=s.client_session_ticket,
                                    obfuscated_ticket_age=obfuscated_age)

                psk_binder_entry = PSKBinderEntry(binder_len=hash_len,
                                                binder=b"\x00" * hash_len)

                ext += TLS_Ext_PreSharedKey_CH(identities=[psk_id],
                                            binders=[psk_binder_entry])
            else:
                # Compute the pre_shared_key extension for out of band PSK
                # (SHA256 is used as default hash function for HKDF for out
                # of band PSK)
                hkdf = TLS13_HKDF("sha256")
                hash_len = hkdf.hash.digest_size
                psk_id = PSKIdentity(identity='Client_identity')
                # XXX see how to not pass binder as argument
                psk_binder_entry = PSKBinderEntry(binder_len=hash_len,
                                                binder=b"\x00" * hash_len)

                ext += TLS_Ext_PreSharedKey_CH(identities=[psk_id],
                                            binders=[psk_binder_entry])
        p.ext = ext
        self.add_msg(p)
        raise self.TLS13_ADDED_CLIENTHELLO()
    
    @ATMT.state()
    def HANDLED_SERVERHELLO(self):
        if hasattr(self, "supported_extensions"):
            pkt = self.cur_pkt
            for ext in pkt.ext:
                if ext.type not in self.supported_extensions:
                    self.supported_extensions.append(ext.type)
        super().HANDLED_SERVERHELLO()

    @ATMT.state()
    def RECEIVED_SERVERFLIGHT2(self):
        if hasattr(self, "supported_extensions"):
            for pkt in self.cur_session.handshake_messages_parsed:
                if isinstance(pkt, TLSNewSessionTicket):
                    if hasattr(self, "server_params"):
                        self.server_params.session_ticket_lifetime = pkt.lifetime
                        self.stop(False)

    @ATMT.state()
    def SSLv2_HANDLED_SERVERFINISHED(self):
        self.get_server_parameters()
        raise self.STOP()
    
    @ATMT.state()
    def HANDLED_SERVERFINISHED(self):
        self.get_server_parameters()
        raise self.STOP()
        pass
    
    @ATMT.state()
    def TLS13_HANDLED_FINISHED(self):
        self.get_server_parameters()
        raise self.STOP()

    def get_server_parameters(self):
        if hasattr(self, "is_client_supported"):
            self.is_client_supported[0] = True

        session = self.cur_session
        if hasattr(self, "supported_ciphers"):
            for pkt in session.handshake_messages_parsed:
                if isinstance(pkt, TLSServerHello):
                    self.supported_ciphers.append(pkt.cipher)

        if hasattr(self, "supported_curves"):
            if session.tls_version == 772:
                curve, _ = session.tls13_server_pubshare.popitem()
                curve_id = list(_tls_named_curves.keys())[list(_tls_named_curves.values()).index(curve)]
                self.supported_curves.append(curve_id)
            else:
                curve = session.client_kx_ecdh_params
                if curve : self.supported_curves.append(curve)           

        if hasattr(self, "supported_protocols"):
            if session.tls_version not in self.supported_protocols:
                self.supported_protocols.append(session.tls_version)

        if hasattr(self, "cipher_prefer"):
            for pkt in session.handshake_messages_parsed:
                if isinstance(pkt, TLSServerHello):
                    self.cipher_prefer.append(pkt.cipher)

        if hasattr(self, "server_params"):
            for pkt in session.handshake_messages_parsed:
                if isinstance(pkt, TLSServerHello):
                    self.server_params.tls_version = session.tls_version
                    self.server_params.chosen_cipher = pkt.cipher
                    self.server_params.random = session.server_random
                    self.server_params.certs = session.server_certs
                    self.server_params.compression_method = pkt.comp
        
        if hasattr(self, "comp_versions_certs"):
            cert: Cert = session.server_certs[0]
            for c in self.comp_versions_certs:
                if c.serial == cert.serial:
                    return
            self.comp_versions_certs.append(cert)


class TLSClientProfile:
    """
    Represents a TLS client profile.
    """

    def __init__(self, client_json_path: str) -> None:        
        with open(client_json_path, 'r', encoding='utf-8') as file:
            json_data = json.load(file)

        self.id:str = json_data.get("id")
        self.platform = json_data.get("platform")
        self.hex_handshake_bytes = json_data.get("hex_handshake_bytes")
        self.lowest_protocol = json_data.get("lowest_protocol")
        self.highest_protocol = json_data.get("highest_protocol")
        self.suite_names = json_data.get("suite_names")
        self.supports_compression = json_data.get("supports_compression")
        self.supports_stapling = json_data.get("supports_stapling")
        self.supports_tickets = json_data.get("supports_tickets")
        self.signature_algorithms = json_data.get("signature_algorithms")
        self.elliptic_curves = json_data.get("elliptic_curves")
        self.supports_npn = json_data.get("supports_npn")
        self.alpn_protocols = json_data.get("alpn_protocols")
        self.supports_server_name_indication = json_data.get("supports_server_name_indication")
        self.client_name = json_data.get("client_name")
        self.client_version = json_data.get("client_version")
        self.protocol_versions_names = json_data.get("protocol_versions_names")
        self.elliptic_curves_names = json_data.get("elliptic_curves_names")
        return
    
    @property
    def id(self) -> str:
        """The ID of the client profile."""
        return self._id
    
    @id.setter
    def id(self, value):
        self._id = value
    
    @property
    def platform(self) -> str:
        """The platform of the client profile."""
        return self._platform

    @platform.setter
    def platform(self, value):
        self._platform = value

    @property
    def hex_handshake_bytes(self) -> str:
        """The hexadecimal representation of the handshake bytes."""
        return self._hex_handshake_bytes
    
    @hex_handshake_bytes.setter
    def hex_handshake_bytes(self, value):
        self._hex_handshake_bytes = value

    @property
    def lowest_protocol(self) -> int:
        """ The lowest supported protocol version."""
        return self._lowest_protocol
    
    @lowest_protocol.setter
    def lowest_protocol(self, value):
        self._lowest_protocol = value

    @property
    def highest_protocol(self) -> int:
        """The highest supported protocol version."""
        return self._highest_protocol
    
    @highest_protocol.setter
    def highest_protocol(self, value):
        self._highest_protocol = value

    @property
    def suite_names(self) -> list[str]:
        """The names of the supported cipher suites."""
        return self._suite_names
    
    @suite_names.setter
    def suite_names(self, value):
        self._suite_names = value

    @property
    def supports_compression(self) -> bool:
        """Indicates if compression is supported."""
        return self._supports_compression
    
    @supports_compression.setter
    def supports_compression(self, value):
        self._supports_compression = value

    @property
    def supports_stapling(self) -> bool:
        """Indicates if OCSP stapling is supported."""
        return self._supports_stapling
    
    @supports_stapling.setter
    def supports_stapling(self, value):
        self._supports_stapling = value

    @property
    def supports_tickets(self) -> bool:
        """Indicates if session tickets are supported."""
        return self._supports_tickets
    
    @supports_tickets.setter
    def supports_tickets(self, value):
        self._supports_tickets = value

    @property
    def signature_algorithms(self) -> list[str]:
        """The supported signature algorithms."""
        return self._signature_algorithms
    
    @signature_algorithms.setter
    def signature_algorithms(self, value):
        self._signature_algorithms = value

    @property
    def elliptic_curves(self) -> list[int]:
        """The supported elliptic curves."""
        return self._elliptic_curves
    
    @elliptic_curves.setter
    def elliptic_curves(self, value):
        self._elliptic_curves = value

    @property
    def supports_npn(self) -> bool:
        """Indicates if Next Protocol Negotiation (NPN) is supported."""
        return self._supports_npn
    
    @supports_npn.setter
    def supports_npn(self, value):
        self._supports_npn = value

    @property
    def alpn_protocols(self) -> list[str]:
        """The supported Application-Layer Protocol Negotiation (ALPN) protocols."""
        return self._alpn_protocols
    
    @alpn_protocols.setter
    def alpn_protocols(self, value):
        self._alpn_protocols = value

    @property
    def supports_server_name_indication(self) -> bool:
        """Indicates if Server Name Indication (SNI) is supported."""
        return self._supports_server_name_indication
    
    @supports_server_name_indication.setter
    def supports_server_name_indication(self, value):
        self._supports_server_name_indication = value

    @property
    def client_name(self) -> str:
        """The name of the client."""
        return self._client_name
    
    @client_name.setter
    def client_name(self, value):
        self._client_name = value

    @property
    def client_version(self) -> str:
        """The version of the client."""
        return self._client_version
    
    @client_version.setter
    def client_version(self, value):
        self._client_version = value

    @property
    def protocol_versions_names(self) -> list[str]:
        """The names of the supported protocol versions."""
        return self._protocol_versions_names
    
    @protocol_versions_names.setter
    def protocol_versions_names(self, value):
        self._protocol_versions_names = value

    @property
    def elliptic_curves_names(self) -> list[str]:
        """The names of the supported elliptic curves."""
        return self._elliptic_curves_names
    
    @elliptic_curves_names.setter
    def elliptic_curves_names(self, value):
        self._elliptic_curves_names = value

class ServerParameters:
    """
    Represents the server parameters.

    This class holds information about the server's TLS parameters, including certificates,
    ciphers, protocols, extensions, and more.
    """
    class CertExtension:
        """
        Represents a certificate extension.
        """

        def __init__(self, content, critical):
            self.content = content
            """The content of the extension."""
            self.critical = True if critical else False
            """Indicates whether the extension is critical or not."""

    def __init__(self,  certs:list[Cert]=[], 
                        ciphers:list[int]=[], 
                        random:bytes="", 
                        protocols:list[int]=[], 
                        compression_method:str="", 
                        ext:list=[], 
                        chosen_cipher:int=None,
                        curves:list[int]=[]) -> None:
        self.certs = certs
        self.ciphers = ciphers
        self.random = random
        self.protocols  = protocols
        self.compression_method = compression_method
        self.extensions = ext
        self.chosen_cipher = chosen_cipher
        self.curves = curves
        self.prefer_server_ciphers_order = False
        self.supported_clients: list[str]  = []
        self.public_key:PubKeyECDSA|PubKeyRSA = None
        self.cert_extensions:dict[str, ServerParameters.CertExtension] = {}
        self.are_all_versions_certs_different: bool = False
        self.tls_version: int = None
        self.session_ticket_lifetime: int = 0

    @property
    def certs(self) -> list[Cert]:
        """The server certificate chain."""
        return self._certs

    @certs.setter
    def certs(self, value:list[Cert]):
        self._certs = value
        if value:
            for ext in self.cert.tbsCertificate.extensions:
                match ext.extnID.oidname:
                    case "keyUsage":
                        self.cert_extensions[ext.extnID.oidname] = self.CertExtension(ext.extnValue.get_keyUsage(), ext.critical)
                    case "extKeyUsage":
                        self.cert_extensions[ext.extnID.oidname] = self.CertExtension(ext.extnValue.get_extendedKeyUsage(), ext.critical)
                    case "subjectAltName":
                        alt_names = []
                        for alt_name in ext.extnValue.subjectAltName:
                            if isinstance(alt_name.generalName, x509.X509_DNSName):
                                alt_names.append(alt_name.generalName.dNSName.val.decode("utf-8"))
                        self.cert_extensions[ext.extnID.oidname] = self.CertExtension(alt_names, ext.critical)
                    case "cRLDistributionPoints":
                        self.cert_extensions[ext.extnID.oidname] = self.CertExtension(ext.extnValue.cRLDistributionPoints, ext.critical)
                    case "authorityInfoAccess":
                        self.cert_extensions[ext.extnID.oidname] = self.CertExtension(ext.extnValue.authorityInfoAccess, ext.critical)
                    case _:
                        pass
            self.public_key = value[0].pubKey        

    @property
    def cert(self) -> Cert:
        """The server certificate"""
        return self.certs[0]
    
    @property
    def cert_validity_period(self) -> int:
        """The validity period of the server certificate in days."""
        return round((time.mktime(self.cert.notAfter) - time.mktime(self.cert.notBefore)) / 60 / 60 / 24)

    @property
    def cert_extensions(self) -> dict[str, CertExtension]:
        """The server certificate extensions. See CertExtension class for more details."""
        return self._cert_extensions
    
    @cert_extensions.setter
    def cert_extensions(self, value:dict):
        self._cert_extensions = value
    
    @property
    def cert_key_usage(self) -> CertExtension:
        """The key usage extension of the server certificate."""
        return self.cert_extensions.get("keyUsage", None)

    @property
    def cert_ext_key_usage(self) -> CertExtension:
        """The extended key usage extension of the server certificate."""
        return self.cert_extensions.get("extKeyUsage", None)
    
    @property
    def cert_subject_alt_name(self) -> CertExtension:
        """The subject alternative name extension of the server certificate."""
        return self.cert_extensions.get("subjectAltName", None)
    
    @property
    def cert_crl_distribution_points(self) -> CertExtension:
        """The CRL distribution points extension of the server certificate."""
        return self.cert_extensions.get("cRLDistributionPoints", None)
    
    @property
    def cert_authority_info_access(self) -> CertExtension:
        """The authority information access extension of the server certificate."""
        return self.cert_extensions.get("authorityInfoAccess", None)
    
    @property
    def validate_cert_chain(self) -> bool:
        """Indicates if the certificate chain is valid.
        
        Validation is tested by checking if the last certificate in the chain is a CA and if the key identifier of the next certificate matches the subject key identifier of the previous one for each certificate in the chain.

        This method is based on recommendations from the ANSSI (Agence Nationnale de la Sécurité des Systèmes d'Information).
        
        Note : if not using subjectKeyIdentifier and authorityKeyIdentifier extensions, the certificate chain will be invalid.
        """
        key_id_list = []
        for cert in self.certs:
            d = {}
            for ext in cert.tbsCertificate.extensions:
                if ext.extnID.oidname == "authorityKeyIdentifier":
                    d['aki'] = ext.extnValue.keyIdentifier.val
                elif ext.extnID.oidname == "subjectKeyIdentifier":
                    d['ski'] = ext.extnValue.keyIdentifier.val
            key_id_list.append(d)
        for i in range(len(key_id_list)-1):
            if not key_id_list[i].get('aki'):
                return False
            if key_id_list[i]['aki'] != key_id_list[i+1]['ski']:
                return False
        return len(key_id_list) > 1 and self.certs[-1].cA

    @property
    def public_key(self) -> PubKeyECDSA|PubKeyRSA:
        """The public key of the server. See scapy.layers.tls.cert for more details."""
        return self._public_key
    
    @public_key.setter
    def public_key(self, value:PubKeyECDSA|PubKeyRSA):
        self._public_key = value

    @property
    def public_key_type(self) -> str:
        """The type of the public key (ECDSA or RSA)."""
        if isinstance(self.public_key, PubKeyECDSA):
            return "ECDSA"
        elif isinstance(self.public_key, PubKeyRSA):
            return "RSA"

    @property
    def public_key_exponent(self) -> int|None:
        """The exponent of the RSA public key. If the public key is not RSA, evaluates to None."""
        if isinstance(self.public_key, PubKeyRSA):
            return self.public_key.pubkey.public_numbers().e
        else:
            return None
    
    @property
    def public_key_curve(self) -> str|None:
        """The name of the elliptic curve used by the ECDSA public key. If the public key is not ECDSA, evaluates to None."""
        if isinstance(self.public_key, PubKeyECDSA):
            return self.public_key.pubkey.curve.name
        else:
            return None
        
    @property
    def public_key_size(self) -> int:
        """The size of the public key in bits."""
        return self.public_key.pubkey.key_size

    @property
    def ciphers(self) -> list[int]:
        """Server supported ciphers identified by their IANA code. If server prefers its own ciphers order, ciphers are ordered by preference, starting with TLS 1.3 ciphers."""
        return self._ciphers

    @ciphers.setter
    def ciphers(self, value):
        self._ciphers = value
    
    @property
    def named_ciphers(self) -> list[str]:
        """The IANA names of the server supported ciphers."""
        return [ _tls_cipher_suites[cipher] for cipher in self.ciphers]

    @property
    def ciphers_nb(self) -> int:
        """The number of supported ciphers."""
        return len(self.ciphers)

    @property
    def chosen_cipher(self) -> int:
        """IANA code of the cipher chosen during last connection."""
        return self._chosen_cipher

    @chosen_cipher.setter
    def chosen_cipher(self, value):
        self._chosen_cipher = value

    @property
    def named_chosen_cipher(self) -> str:
        """The IANA name of the chosen cipher."""
        return _tls_cipher_suites[self.chosen_cipher]

    @property
    def random(self) -> bytes:
        """Server's random bytes."""
        return self._random

    @random.setter
    def random(self, value):
        self._random = value

    @property
    def random_hex(self) -> str:
        """The hexadecimal representation of the server's random bytes."""
        return self.random.hex().upper()
    
    @property
    def protocols(self) -> list[int]:
        """The server supported protocols."""
        return self._protocols
    
    @protocols.setter 
    def protocols(self, value):
        self._protocols = value

    @property
    def named_protocols(self) -> list[str]:
        """The names of the server supported protocols."""
        return [ _tls_version[protocol] for protocol in self.protocols]

    @property
    def tls_version(self) -> int:
        """The server's last connection TLS version."""
        return self._tls_version
    
    @tls_version.setter
    def tls_version(self, value):
        self._tls_version = value
    
    @property
    def named_tls_version(self) -> str:
        """The name of the server's last connection TLS version."""
        return _tls_version[self.tls_version]

    @property
    def highest_protocol(self) -> int:
        """The highest supported protocol."""
        return self.protocols[-1]

    @property
    def highest_legacy_protocol(self) -> int|None:
        """The highest supported legacy protocol (<TLS 1.3). If the server does not support legacy protocols, evaluates to None."""
        if self.highest_protocol != 772:
            return self.highest_protocol
        elif len(self.protocols) > 1:
            return self.protocols[-2]
        else : return None
    
    @property
    def compression_method(self) -> str:
        """The server's supported compression method."""
        return self._compression_method
    
    @compression_method.setter
    def compression_method(self, value):
        self._compression_method = value
    
    @property
    def supports_compression(self) -> bool:
        """Indicates if the server supports compression."""
        return self.compression_method != [0]

    @property
    def extensions(self) -> list[int]:
        """The server supported TLS extensions. See scapy.layers.tls.extensions for more details."""
        return self._ext
    
    @extensions.setter
    def extensions(self, value):
        self._ext = value

    @property
    def named_extensions(self) -> list[str]:
        """The names of the server supported extensions."""
        return [ _tls_ext[ext] for ext in self.extensions]

    @property
    def prefer_server_ciphers_order(self) -> bool:
        """Indicates if the server prefers its own ciphers order"""
        return self._prefer_server_ciphers
    
    @prefer_server_ciphers_order.setter
    def prefer_server_ciphers_order(self, value:bool):
        self._prefer_server_ciphers = value
    
    @property
    def curves(self) -> list[int]:
        """The server supported elliptic curves. See scapy.layers.tls.crypto.groups for more details."""
        return self._curves
    
    @curves.setter
    def curves(self, value):
        self._curves = value

    @property
    def named_curves(self) -> list[str]:
        """The names of the server supported elliptic curves."""
        return [ _tls_named_curves[curve] for curve in self.curves]
    
    @property
    def random_startswith_timestamp(self) -> bool:
        """Indicates if the random bytes start with a UNIX timestamp.
        
        Note: This is a heuristic and may not always be accurate.
        """
        try:
            # Check if the random bytes start with a timestamp
            timestamp_int = int.from_bytes(self.random[:4], byteorder='big')
            timestamp = datetime.datetime.fromtimestamp(timestamp_int)
            return True
        except ValueError or OverflowError:
            return False
        
    @property
    def is_0RTT(self) -> bool:
        """Indicates if 0-RTT is supported."""
        return 0x2a in self.extensions
    
    @property
    def supported_clients(self) -> list[str]:
        """The supported clients."""
        return self._supported_clients
    
    @supported_clients.setter
    def supported_clients(self, value):
        self._supported_clients = value

    @property
    def are_all_versions_certs_different(self) -> bool:
        """Indicates if all protocols have different certificates."""
        return self._all_protocols_certs_different
    
    @are_all_versions_certs_different.setter
    def are_all_versions_certs_different(self, value:bool):
        self._all_protocols_certs_different = value

    @property
    def ocsp_stapling(self) -> bool:
        """Indicates if OCSP stapling is supported."""
        return "status_request" in self.extensions

    @property
    def session_ticket_lifetime(self) -> int:
        """The session ticket lifetime in seconds. If the server does not support session tickets, evaluates to 0."""
        return self._session_ticket_lifetime
    
    @session_ticket_lifetime.setter
    def session_ticket_lifetime(self, value:int):
        self._session_ticket_lifetime = value

    def get(self, path:str, default=None,  sep='.') :
        """Gets the property by its dot path."""
        if not isinstance(path, str):
            raise TypeError(f'Invalid path type: {type(path)}')
        split_path = path.split(sep)
        value = self
        for key in split_path:
            value = getattr(value, key, default)
        return value

@dataclass   
class Rule:
    """
    Represents a rule for TLS checking.
    """
    name: str
    """The name of the rule."""
    title: str
    """The title of the rule."""
    description: str
    """The description of the rule."""
    requirements: dict
    """The requirements of the rule."""
    mitigation: str
    """The mitigation for the rule."""
    critical: bool = True
    """Indicates if the rule is critical."""
    auditable: bool = True
    """Indicates if the rule is auditable."""
    passed: bool = False
    """Indicates if the rule has passed."""

class RuleCollection:
    """
    Represents a collection of rules.

    The collection is iterrable and can be accessed by index.
    
    Length of the collection can be obtained by len() method.
    """
    def __init__(self, json_file:str):
        """Initializes the RuleCollection object with the json rule file passed as argument.

        Args:
        - json_file (str): The path to the JSON file containing the rules.

        Raises:
        - JSONDecodeError: If the JSON file cannot be decoded.
        - ValueError: If an error occurs while reading the JSON file.
        """
        try:
            self.__rules: list[Rule] = []
            with open('./Ressources/rules/' + json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for rule_key, rule_data in data.items():
                    rule = Rule(
                        rule_key,
                        rule_data['title'],
                        rule_data['description'],
                        rule_data.get('requirements', {}),
                        rule_data['mitigation'],
                        rule_data.get('critical', True),
                        rule_data.get('auditable', True)
                    )
                    self.__rules.append(rule)
        except json.JSONDecodeError as e:
            print(f"JSON decoding error : {e}")
        except ValueError as ve:
            print(f"An error occured while reading the JSON file : {ve}")
        self.repRule = './Ressources/rules/'

    def __len__(self):
        return len(self.__rules)

    def __iter__(self):
        return iter(self.__rules)
    
    def __next__(self):
        return next(self.__rules)
    
    def __getitem__(self, index):
        return self.__rules[index]
    
class Results:
    """
    Represents the results of a TLS check.

    Attributes:
        certs (list[Cert]): The server certificates.
        ciphers (list[str]): The supported cipher suites.
        random (str): The random value used during the TLS handshake.
        protocols (list[str]): The supported TLS protocols.
        supports_compression (bool): Indicates if compression is supported.
        extensions (list[str]): The supported TLS extensions.
        key_size (int): The size of the server's public key.
        prefer_server_ciphers (bool): Indicates if the server prefers its own cipher suite order.
        supported_clients: The supported client profiles.
        cert_extensions: The extensions in the server's certificate.
        all_protocols_certs_different: Indicates if the certificates for all TLS versions are different.
        ocsp_stapling: Indicates if OCSP stapling is supported.
        curves: The supported elliptic curves.
        chosen_cipher: The chosen cipher suite during the handshake.
        random_start_with_timestamp: Indicates if the random value starts with a timestamp.
        public_key_type: The type of the server's public key.
        public_key_curve: The curve used by the server's public key.
        nb_rules (int): The total number of rules.
        nb_tested_rules (int): The number of rules that have been tested.
        nb_passed (int): The number of rules that have passed.
        nb_critical (int): The number of critical rules.
        nb_critical_failed (int): The number of critical rules that have failed.
        grade_key (float): The grade for the key size.
        grade_protocol (float): The grade for the supported protocols.
        grade_ciphers (float): The grade for the supported cipher suites.
        grade_cert (float): The grade for the server's certificate.
        grade_cert_str (str): The string representation of the certificate grade.
        grade_rules (float): The grade for the tested rules.
        grade_rules_str (str): The string representation of the rules grade.
        grade_parameters (float): The grade for the overall parameters.
        grade_parameters_str (str): The string representation of the parameters grade.
        auditable_rules (list[Rule]): The auditable rules.
        not_auditable_rules (list[Rule]): The rules that are not auditable.
        failed_rules (list[Rule]): The rules that have failed.
    """
    def __init__(self, server_param: ServerParameters, rules: RuleCollection, user_args) -> None:
        """
        Initializes a new instance of the Results class.

        Args:
            server_param (ServerParameters): The server parameters.
            rules (RuleCollection): The collection of rules.
            user_args: The user arguments.

        Returns:
            None
        """
        # Server parameters
        self.certs = server_param.certs
        self.ciphers = server_param.named_ciphers
        self.random = server_param.random
        self.protocols = server_param.named_protocols
        self.supports_compression = server_param.supports_compression
        self.extensions = server_param.named_extensions
        self.key_size = server_param.public_key_size
        self.prefer_server_ciphers = server_param.prefer_server_ciphers_order
        self.supported_clients = server_param.supported_clients
        self.cert_extensions = server_param.cert_extensions
        self.all_protocols_certs_different = server_param.are_all_versions_certs_different
        self.ocsp_stapling = server_param.ocsp_stapling
        self.curves = server_param.named_curves
        self.chosen_cipher = server_param.named_chosen_cipher
        self.random_start_with_timestamp = server_param.random_startswith_timestamp
        self.public_key_type = server_param.public_key_type
        self.public_key_curve = server_param.public_key_curve
        self.public_key_size = server_param.public_key_size

        # Client profiles
        self.client_profiles = user_args.client_profiles
        # Rules
        self.rules = rules
        self.auditable_rules:list[Rule] = []
        self.not_auditable_rules:list[Rule] = [] 
        self.failed_rules:list[Rule] = []
        self.nb_rules = 0
        self.nb_tested_rules = 0        
        self.nb_passed = 0
        self.nb_critical = 0
        self.nb_critical_failed = 0
        # Grading
        self.grade_key = 1
        self.grade_protocol = 1
        self.grade_ciphers = 1
        self.grade_cert = 1
        self.grade_cert_str = "F"
        self.grade_rules = 0
        self.grade_rules_str = "F"
        self.grade_parameters = 0
        self.grade_parameters_str = "F"
        
    @property
    def certs(self) :
        return self._certs
    
    @certs.setter
    def certs(self, value: list[Cert]) -> None:
        self._certs = value
    
    @property
    def random(self) -> str:
        return self._random
    
    @random.setter
    def random(self, value: str) -> None:
        self._random = value
    
    @property
    def protocols(self) -> list[str]:
        return self._protocols
    
    @protocols.setter
    def protocols(self, value: list[str]) -> None:
        self._protocols = value

    @property
    def supports_compression(self) -> bool:
        return self._supports_compression
    
    @supports_compression.setter
    def supports_compression(self, value: bool) -> None:
        self._supports_compression = value

    @property
    def extensions(self) -> list[str]:
        return self._extensions
    
    @extensions.setter
    def extensions(self, value: list[str]) -> None:
        self._extensions = value

    @property
    def prefer_server_ciphers(self) -> bool:
        return self._prefer_server_ciphers
    
    @prefer_server_ciphers.setter
    def prefer_server_ciphers(self, value: bool) -> None:
        self._prefer_server_ciphers = value

    @property
    def chosen_cipher(self) -> str:
        return self._chosen_cipher
    
    @chosen_cipher.setter
    def chosen_cipher(self, value: str) -> None:
        self._chosen_cipher = value

    @property
    def cert_extensions(self):
        return self._cert_extensions
    
    @cert_extensions.setter
    def cert_extensions(self, value):
        self._cert_extensions = value

    @property
    def rules(self) -> RuleCollection:
        return self._rules
    
    @rules.setter
    def rules(self, value: RuleCollection) -> None:
        self._rules = value

    @property
    def nb_rules(self) -> int:
        return self._nb_rules
    
    @nb_rules.setter
    def nb_rules(self, value: int) -> None:
        self._nb_rules = value

    @property
    def nb_tested_rules(self) -> int:
        return self._nb_tested_rules
    
    @nb_tested_rules.setter
    def nb_tested_rules(self, value: int) -> None:
        self._nb_tested_rules = value

    @property
    def nb_passed(self) -> int:
        return self._nb_passed
    
    @nb_passed.setter
    def nb_passed(self, value: int) -> None:
        self._nb_passed = value
    
    @property
    def nb_failed(self) -> int:
        return self.nb_tested_rules - self.nb_passed
    
    @property
    def nb_critical_failed(self) -> int:
        return self._nb_critical_failed
    
    @nb_critical_failed.setter
    def nb_critical_failed(self, value: int) -> None:
        self._nb_critical_failed = value

    @property
    def key_size(self) -> int:
        return self._key_size
    
    @key_size.setter
    def key_size(self, value: int) -> None:
        self._key_size = value

    @property
    def grade_key(self) -> float:
        return self._grade_key
    
    @grade_key.setter
    def grade_key(self, value: float) -> None:
        self._grade_key = value

    @property
    def grade_protocol(self) -> float:
        return self._grade_protocol

    @grade_protocol.setter
    def grade_protocol(self, value: float) -> None:
        self._grade_protocol = value
    
    @property
    def grade_ciphers(self) -> float:
        return self._grade_ciphers
    
    @grade_ciphers.setter
    def grade_ciphers(self, value: float) -> None:
        self._grade_ciphers = value

    @property
    def grade_cert(self) -> float:
        return self._grade_cert
    
    @grade_cert.setter
    def grade_cert(self, value: float) -> None:
        self._grade_cert = value

    @property
    def nb_critical(self) -> int:
        return self._nb_critical
    
    @nb_critical.setter
    def nb_critical(self, value: int) -> None:
        self._nb_critical = value

    @property
    def supported_clients(self):
        return self._supported_clients
    
    @supported_clients.setter
    def supported_clients(self, value):
        self._supported_clients = value

    @property
    def auditable_rules(self):
        return self._auditable_rules
    
    @auditable_rules.setter
    def auditable_rules(self, value):
        self._auditable_rules = value

    @property
    def failed_rules(self):
        return self._failed_rules
    
    @failed_rules.setter
    def failed_rules(self, value):
        self._failed_rules = value

    @property
    def not_auditable_rules(self):
        return self._not_auditable_rules
    
    @not_auditable_rules.setter
    def not_auditable_rules(self, value):
        self._not_auditable_rules = value

    def grading_rules(self) -> None:
        """
        Calculate grading of the rules.
        """       
        nb_rules_not_crit = 0
        self.nb_tested_rules = 0
        self.nb_passed = 0
        self.nb_critical = 0
        self.nb_critical_failed = 0
        self.nb_rules = 0
        
        for rule in self.rules:
            self.nb_rules += 1
            if rule.auditable:
                self.nb_tested_rules += 1
                if rule.passed:
                    self.nb_passed += 1
                else:
                    if rule.critical:
                        self.nb_critical_failed += 1
                if not rule.critical:
                    nb_rules_not_crit += 1
                else:
                    self.nb_critical += 1
        self.grade_rules = round((self.nb_passed) / (self.nb_tested_rules - nb_rules_not_crit ) * 100)

    def grading_parameters(self) -> None:
        if self.key_size < 128:
            self.grade_key = 0
        elif self.key_size < 256:
            self.grade_key = 0.8
        elif self.key_size >= 256:
            self.grade_key = 1

        if len(self.protocols) == 1:
            if "TLS 1.3" in self.protocols:
                self.grade_protocol *= 1
            elif "TLS 1.2" in self.protocols:
                self.grade_protocol *= 0.90 
            else:
                self.grade_protocol *= 0
        elif len(self.protocols) == 2:
            if "TLS 1.3" in self.protocols and "TLS 1.2" in self.protocols:
                self.grade_protocol *= 0.95
            else:
                self.grade_protocol *= 0
        else:
            self.grade_protocol *= 0

        self.grading_ciphers()

        self.grade_parameters = (self.grade_key + self.grade_protocol + self.grade_ciphers) / 3 * 100
        
    
    def grading_ciphers(self) -> None:
        """
        Grade the ciphers based on wheter the cipher suites are recommended or not.

        Returns:
            None
        """ 
        strong_ciphers = [
                            "TLS_AES_256_GCM_SHA384",
                            "TLS_AES_128_GCM_SHA256",
                            "TLS_AES_128_CCM_SHA256",
                            "TLS_CHACHA20_POLY1305_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
                            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"                           
                        ]
        
        degraded_ciphers = [
                            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_DHE_RSA_WITH_AES_128_CCM",
                            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
                            "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
                            "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
                            "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
                            "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
                            "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
                            "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
                            "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
                            "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_DHE_PSK_WITH_AES_256_CCM",
                            "TLS_DHE_PSK_WITH_AES_128_CCM",
                            "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
                            "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
                            "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
                            "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
                            "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
                            "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
                            "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"
                        ]
        
        for cipher in self.ciphers:
            if cipher in strong_ciphers:
                self.grade_ciphers *= 1
            elif cipher in degraded_ciphers:
                self.grade_ciphers = 0.8
            else:
                self.grade_ciphers = 0

    def grading_certificates(self) -> None:
        """
        Grade the certificates based on certain criteria.

        Returns:
            None
        """
        sig_alg = self.certs[0].sigAlg.upper()       
        if "SHA1" in sig_alg or "MD5" in sig_alg :
            self.grade_cert *= 0
        elif "SHA2" in sig_alg or \
             "SHA384" in sig_alg or \
             "SHA512" in sig_alg :
            self.grade_cert *= 1
        else:
            self.grade_cert -= 1
        
        self.grade_cert *= 100
        
    def grading_letters(self, grade: float) -> str:
        """
        Assigns letter grades based on the numerical grades.

        The letter grades are assigned according to the following criteria:
        - A+ for grades >= 98
        - A for grades >= 95
        - A- for grades >= 90
        - B for grades >= 80
        - C for grades >= 70
        - D for grades >= 60
        - E for grades >= 50
        - F for grades < 50

        Args:
            grade (float): The numerical grade.

        Returns:
            str: The letter grade.
        """
        if grade >= 98:
            return "A+"
        elif grade >= 95:
            return "A"
        elif grade >= 90:
            return "A-"
        elif grade >= 80:
            return "B"
        elif grade >= 70:
            return "C"
        elif grade >= 60:
            return "D"
        elif grade >= 50:
            return "E"
        else:
            return "F"

    def grading_letters_color(self, grade_str: str) -> str:
        """
        Assigns color codes to the grade string based on the letter grade.

        Args:
            grade_str (str): The grade string to be colored.

        Returns:
            str: The colored grade string.
        """
        if grade_str == "A+":
            return "[green3]A+[/green3]"
        elif grade_str == "A":
            return "[green3]A[/green3]"
        elif grade_str == "A-":
            return "[green3]A-[/green3]"
        elif grade_str == "B":
            return "[bright_yellow]B[/bright_yellow]"
        elif grade_str == "C":
            return "[bright_yellow]C[/bright_yellow]"
        elif grade_str == "D":
            return "[orange1]D[/orange1]"
        elif grade_str == "E":
            return "[orange1]E[/orange1]"
        else:
            return "[red1]F[/red1]"
    
    def filter_rules(self) -> None:
        """
        Filter the rules based on their results.
        """        
        for rule in self.rules:
            if rule.auditable:
                self.auditable_rules.append(rule)
            elif not rule.auditable:
                self.not_auditable_rules.append(rule)
            elif not rule.passed:
                self.failed_rules.append(rule)

    def grading(self) -> None:
        self.grading_rules()
        self.grading_parameters()
        self.grading_certificates()
        self.grade_rules_str = self.grading_letters(self.grade_rules)
        self.grade_parameters_str = self.grading_letters_color(self.grading_letters(self.grade_parameters))
        self.grade_cert_str = self.grading_letters_color(self.grading_letters(self.grade_cert))    

    def grading_without_rules(self) -> None:
        self.grading_parameters()
        self.grading_certificates()
        self.grade_parameters_str = self.grading_letters_color(self.grading_letters(self.grade_parameters))
        self.grade_cert_str = self.grading_letters_color(self.grading_letters(self.grade_cert))

    def comment_key_size(self, grade_key: float) -> str:
        if grade_key == 1:
            return "Taille de clé >= 256 bits, conforme aux recommandations de sécurité optimale."
        elif grade_key == 0.8:
            return "Taille de clé entre 128 et 255 bits, considérée comme acceptable mais non idéale."
        else:
            return "Taille de clé < 128 bits, insuffisante pour une sécurité adéquate."

    def comment_protocol(self, grade_protocol: float) -> str:
        if grade_protocol == 1:
            return "Utilisation de TLS 1.3, conforme aux meilleures pratiques."
        elif grade_protocol < 1 and grade_protocol > 0:
            return "Utilisation de TLS 1.2, nécessite des améliorations pour atteindre les meilleures pratiques."
        else:
            return "Protocole obsolète détecté, nécessite une mise à jour immédiate."

    def comment_cipher(self, grade_ciphers: float) -> str:
        if grade_ciphers == 1:
            return "Suites cryptographiques fortes utilisées, conforme aux recommandations."
        elif grade_ciphers == 0.8:
            return "Utilisation de suites cryptographiques avec des clés de 128 bits, acceptable mais non idéale."
        else:
            return "Suites cryptographiques faibles ou non sécurisées détectées, mise à jour recommandée."

    def comment_certificate(self, grade_cert: float) -> str:
        if grade_cert == 100:
            return "Certificat conforme aux meilleures pratiques (SHA-256 ou supérieur)."
        elif grade_cert >= 80:
            return "Certificat généralement conforme, mais des améliorations mineures sont possibles."
        elif grade_cert >= 50:
            return "Certificat avec des problèmes modérés, tel que l'usage d'algorithmes de signature faibles."
        elif grade_cert > 0:
            return "Certificat fortement non conforme aux recommandations de sécurité, nécessite une attention immédiate."
        else:
            return "Aucun certificat valide trouvé ou certificat utilisant des algorithmes de signature obsolètes ou non sécurisés."
   

    def print_analysed_rules(self) -> None:
        """
        Print the list of rules analysed and their results.
        """
        table = Table(title="[bold deep_sky_blue1]Listes des règles analysées[bold deep_sky_blue1]", width=180, show_lines=True)
        table.add_column("Titre", justify="center", vertical="middle")  
        table.add_column("Résumé", justify="center", vertical="middle")  
        table.add_column("Détails", justify="center", vertical="middle")  
        table.add_column("Mitigation", justify="center", vertical="middle")  
        table.add_column("Critique", justify="center", vertical="middle") 
        table.add_column("Validation", justify="center", vertical="middle") 
        table.add_column("Auditable", justify="center", vertical="middle") 
        for rule in self.rules:
            if rule.auditable:
                table.add_row(
                            rule.name,
                            rule.title,
                            rule.description,
                            str(rule.mitigation),
                            "[bold ]Critical[/bold]" if rule.critical else "Not Critical",
                            "[bold green3]Passed[/bold green3]" if rule.passed else "[red]Failed[/red]",  
                            "[bold green3]Auditable[/bold green3]" if rule.auditable else "[bright_yellow]Not Auditable[/bright_yellow]")
    
        print(table)


    def print_non_auditable_rules(self) -> None:
        """
        Print the list of rules analysed and their results.
        """
        table = Table(title="[bold deep_sky_blue1]Listes des règles non auditables[bold deep_sky_blue1]", width=180, show_lines=True)
        table.add_column("Titre", justify="center", vertical="middle")  
        table.add_column("Résumé", justify="center", vertical="middle")  
        table.add_column("Détails", justify="center", vertical="middle")  
        table.add_column("Mitigation", justify="center", vertical="middle")  
        table.add_column("Auditable", justify="center", vertical="middle") 
        for rule in self.rules:
            if not rule.auditable:
                table.add_row(
                            rule.name,
                            rule.title,
                            rule.description,
                            str(rule.mitigation),
                            "[green3]Auditable[/green3]" if rule.auditable else "[bright_yellow]Not Auditable[/bright_yellow]"
                        )
        print(table)
        explanation = ("Les règles non auditables sont des règles qui ne peuvent pas être testées automatiquement du fait qu'elles reposent sur des moyens organisationnels ou qu'il a été impossible de les valider du point de vue du script. Elles nécessitent donc une intervention manuelle pour être vérifiées")
        panel = Panel(explanation, title="[bold]Note sur les règles non auditables[/bold]", expand=False, border_style="green3", style="italic on black")
        console = Console()
        console.print(panel)

    def colorize_cipher(self, cipher: str) -> str:
        """
        Colorize the cipher based on its value.

        Args:
            cipher (str): The cipher to be colorized.

        Returns:
            str: The colorized cipher.
        """
        strong_ciphers = [
                            "TLS_AES_256_GCM_SHA384",
                            "TLS_AES_128_GCM_SHA256",
                            "TLS_AES_128_CCM_SHA256",
                            "TLS_CHACHA20_POLY1305_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
                            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"                           
                        ]
        
        degraded_ciphers = [
                            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_DHE_RSA_WITH_AES_128_CCM",
                            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
                            "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
                            "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
                            "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
                            "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
                            "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
                            "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
                            "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
                            "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_DHE_PSK_WITH_AES_256_CCM",
                            "TLS_DHE_PSK_WITH_AES_128_CCM",
                            "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
                            "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
                            "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
                            "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
                            "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
                            "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
                            "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"
                        ]

        if cipher in strong_ciphers:
            return f"[green3]{cipher}[/green3]"
        elif cipher in degraded_ciphers:
            return f"[bright_yellow]{cipher}[/bright_yellow]"
        else:
            return f"[red]{cipher}[/red]"

    def colorize_extension(self, extension: str, tls_version: list[str]) -> str:
        """
        Colorize the extension based on its value.

        Args:
            extension (str): The extension to be colorized.

        Returns:
            str: The colorized extension.
        """
        recommended_ext_gen = [
                                "server_name",
                                "supported_groups",
                                "signature_algorithms",        
                                "renegotiation_info",
                                "signed_certificate_timestamp",
                                "sct"
                            ]

        recommended_ext_tls2 = [
                                "encrypt_then_mac",
                                "extended_master_secret"
                            ]
        
        recommended_ext_tls3 = [
                                "supported_versions",
                                "key_share"
                            ]

        bad_ext = [
                "max_fragment_length",
                "client_certificate_url",
                "truncate_hmac",
                "client_authz",
                "server_authz",
                "cert_type",
                "ec_point_formats",
                "heartbeat",
                "client_certificate_type",
                "server_certificate_type",
                "early_data"
                ]

        if extension in bad_ext:
            return f"[red]{extension}[/red]"
        elif extension in recommended_ext_gen:        
            return f"[green3]{extension}[/green3]"
        elif extension in recommended_ext_tls2 and "TLS 1.2" in tls_version:
            return f"[green3]{extension}[/green3]"
        elif extension in recommended_ext_tls3 and "TLS 1.3" in tls_version:
            return f"[green3]{extension}[/green3]"
        else:
            return extension
    
    def colorized_curves(self, curve: str) -> str:
        """
        Colorize the curve based on its value.

        Args:
            curve (str): The curve to be colorized.

        Returns:
            str: The colorized curve.
        """
        recommended_curves = [
                            "secp256r1",
                            "secp384r1",
                            "secp521r1",
                            "x25519",
                            "x448",
                            "brainpoolP256r1",
                            "brainpoolP384r1",
                            "brainpoolP512r1",
                            "brainpoolP256r1tls13",
                            "brainpoolP384r1tls13",
                            "brainpoolP512r1tls13",
                        ]

        if curve in recommended_curves:
            return f"[green3]{curve}[/green3]"
        else:
            return curve
        
    def colorized_key_type(self, key_type: str) -> str:
        """
        Colorize the key type based on its value.

        Args:
            key_type (str): The key type to be colorized.

        Returns:
            str: The colorized key type.
        """
        recommended_key_type = [                            
                            "ECDSA",
                            "EdDSA",
                            "DH",
                            "DHE",
                            "ECDH"
                        ]

        if key_type in recommended_key_type:
            return f"[green3]{key_type}[/green3]"
        elif key_type == "RSA":
            return f"[red]{key_type}[/red]"
        else:
            return key_type
    
    def colorized_key_size(self, key_size: int) -> str:
        """
        Colorize the key size based on its value.

        Args:
            key_size (int): The key size to be colorized.

        Returns:
            str: The colorized key size.
        """
        if key_size >= 256:
            return f"[green3]{key_size} bits[/green3]"
        elif key_size >= 128:
            return f"[bright_yellow]{key_size} bits[/bright_yellow]"
        else:
            return f"[red]{key_size} bits[/red]"
    
    def print_server_parameters(self) -> None:
        """
        Print the connnexion parameters of the server.
        """
        table = Table(title="[bold deep_sky_blue1]Liste des paramètres de connexion du serveur[bold deep_sky_blue1]", width=180, show_lines=True)
        table.add_column("Paramètres de la connexion", justify="left", vertical="middle")
        table.add_column("Valeurs", justify="center", vertical="middle", no_wrap=True)
        str_protocol = ""
        for protocol in self.protocols:
            if protocol in ["TLS 1.3"]:
                str_protocol += f"[green3]{protocol}[/green3]\n"
            elif protocol not in ["TLS 1.3", "TLS 1.2"]:
                str_protocol += f"[red]{protocol}[/red]\n"
            else:
                str_protocol += f"{protocol}\n"
        table.add_row("Protocoles utilisés :", str_protocol.rstrip("\n")) 
        str_cipher = ""
        for i, cipher in enumerate(self.ciphers):
            if i == len(self.ciphers) - 1:
                str_cipher += self.colorize_cipher(cipher)
            else:
                str_cipher += self.colorize_cipher(cipher) + "\n"
        table.add_row("Suites cryptographique :",  str_cipher)
        table.add_row("Préférences des suites du serveur :", "[green3]Oui[/green3]" if self.prefer_server_ciphers else "[red]Non[/red]")
        table.add_row("Suite de chiffrement utilisée :", self.colorize_cipher(self.chosen_cipher))
        table.add_row("Utilisation de la compression :", "[red]Oui[/red]" if self.supports_compression else "[green3]Non[/green3]")
        str_curves = ""
        for i, curve in enumerate(self.curves):
            if i == len(self.curves) - 1:
                str_curves += self.colorized_curves(curve)
            else:
                str_curves += self.colorized_curves(curve) + "\n"
        if len(self.curves) == 0:
            str_curves = "[red]Aucune courbe elliptique supportée[/red]"
        table.add_row("Courbes elliptiques supportées :", str_curves)
        str_extension = ""
        for i, extension in enumerate(self.extensions):
            if i == len(self.extensions) - 1:
                str_extension += self.colorize_extension(extension, self.protocols)
            else:
                str_extension += self.colorize_extension(extension, self.protocols) + "\n"
        table.add_row("Extensions utilisés :", str_extension)
        table.add_row("Aléa commençant avec un timestamp :",  "[red]Oui[/red]" if self.random_start_with_timestamp else "[green3]Non[/green3]")
        table.add_row("Utilisation de l'agrafage OCSP :", "[green3]Oui[/green3]" if self.ocsp_stapling else "[red]Non[/red]")
        table.add_row("Type de clé publique :", self.colorized_key_type(self.public_key_type))
        table.add_row("Taille de la clé publique :", self.colorized_key_size(self.public_key_size))
        table.add_row("Courbe de la clé publique :", self.colorized_curves(self.public_key_curve))
        print(table)

    def format_extension_content(self, ext_name, content):
        # Cette méthode choisit le formatage approprié selon le nom de l'extension
        if ext_name == "subjectAltName":
            # Suppose que content est déjà une liste de chaînes
            return ', '.join(content)
        elif ext_name in ["keyUsage", "extKeyUsage"]:
            # Pour keyUsage et extKeyUsage où le contenu est déjà adapté
            return ', '.join(content)
        else:
            return "Extension non prise en charge pour l'affichage"

    
    def print_cert_value(self) -> None:
        """
        Print the certificates values.
        """
        table = Table(title="[bold deep_sky_blue1]Affichage du certificat[bold deep_sky_blue1]", width=180, show_lines=True)
        table.add_column("Paramètres", justify="left", vertical="middle")
        table.add_column("Valeurs", justify="center", vertical="middle", no_wrap=False)

        # Ajouter les informations de base du certificat
        table.add_row("Sujet", str(self.certs[0].subject['commonName']))        
        table.add_row("Emetteur", str(self.certs[0].issuer['commonName']))
        table.add_row("Emetteur Organisation", str(self.certs[0].issuer['organizationName']))
        table.add_row("Emetteur Pays", str(self.certs[0].issuer['countryName']))
        table.add_row("Valide du", time.strftime("%Y-%m-%d %H:%M:%S", self.certs[0].notBefore))
        table.add_row("Valide jusqu'au", time.strftime("%Y-%m-%d %H:%M:%S", self.certs[0].notAfter))
        table.add_row("Algorithme de Signature", str(self.certs[0].sigAlg))
        table.add_row("Auto-signé", "Oui" if self.certs[0].isSelfSigned() else "Non")


        # Ajouter les extensions
        for ext_name in ["keyUsage", "extKeyUsage", "subjectAltName"]:
            if ext_name in self.cert_extensions:
                ext = self.cert_extensions[ext_name]
                value = self.format_extension_content(ext_name, ext.content)
                critical = " (Critique)" if ext.critical else ""
                table.add_row(f"Extension - {ext_name}", f"{value}{critical}")

        print(table)

    def print_supported_clients(self) -> None:
        """
        Print the list of supported clients.
        """
        table = Table(title="[bold deep_sky_blue1]Liste des clients supportés[bold deep_sky_blue1]", width=180, show_lines=True)
        table.add_column("Clients", justify="center", vertical="middle")
        table.add_column("Supportés", justify="center", vertical="middle")
        for client in self.client_profiles:
            if client in self.supported_clients:
                table.add_row(client, "[green3]SUPPORTED[/green3]")
            else:
                table.add_row(client, "[red]NOT SUPPORTED[/red]")
        print(table)
    
    # TODO 
    def print_grading_rules(self) -> None:
        """
        Print the grading of the rules.
        """
        table = Table(title="[bold deep_sky_blue1]Note de l'analyse[bold deep_sky_blue1]", width=180, show_lines=True)
        table.add_column("Nombre de règles", justify="center", vertical="middle")
        table.add_column("Nombre de règles testées", justify="center", vertical="middle")
        table.add_column("Nombre de règles critique", justify="center", vertical="middle")
        table.add_column("Nombre de règles réussies", justify="center", vertical="middle")        
        table.add_column("Nombre de règles critiques échouées", justify="center", vertical="middle") 
        table.add_column("Nombre de règles échouées", justify="center", vertical="middle")
        table.add_column("Pourcentage", justify="center", vertical="middle")
        table.add_column("Note", justify="center", vertical="middle")
        table.add_row(
                str(self.nb_rules),
                str(self.nb_tested_rules),
                str(self.nb_critical),
                f"[green3]{str(self.nb_passed)}[/green3]",                
                f"[red]{self.nb_critical_failed}[/red]", 
                str(self.nb_failed),  
                f"{self.grade_rules}%",  
                self.grading_letters_color(self.grade_rules_str)
        )
        print(table)

    def print_grading_summary(self) -> None:
        """
        Affiche un résumé des notes obtenues dans les différentes catégories d'évaluation.
        """

        table = Table(title="[bold deep_sky_blue1]Résumé des Notes d'Évaluation[/bold deep_sky_blue1]", width=180, show_lines=True, title_justify="center")

        table.add_column("Catégorie", justify="center", style="bold")
        table.add_column("Pourcentage", justify="center")
        table.add_column("Note", justify="center")
        table.add_column("Commentaire", justify="center")
        table.add_column("Recommandation", justify="center")
        

        # Ajout des lignes pour chaque catégorie évaluée
        table.add_row("Taille de la Clé", f"{self.grade_key * 100:.0f}%",
                     self.grading_letters_color(self.grading_letters(self.grade_key * 100)), self.comment_key_size(self.grade_key),
                  "256 bits ou plus recommandé pour une sécurité optimale.")
        table.add_row("Protocoles", f"{self.grade_protocol * 100:.0f}%",
                    self.grading_letters_color(self.grading_letters(self.grade_protocol * 100)),
                    self.comment_protocol(self.grade_protocol),
                  "TLS 1.3 est recommandé pour la meilleure sécurité. TLS 1.2 est également accepté.")
        table.add_row("Suites Cryptographiques", f"{self.grade_ciphers * 100:.0f}%",
                    self.grading_letters_color(self.grading_letters(self.grade_ciphers * 100)),
                    self.comment_cipher(self.grade_ciphers),
                  "Veillez à utiliser des suites cryptographiques qui sont recommendé .")
        table.add_row("Certificats", f"{self.grade_cert:.0f}%",
                    self.grading_letters_color(self.grading_letters(self.grade_cert)),
                    self.comment_certificate(self.grade_cert),
                  "Évitez les certificats auto-signés et utilisez SHA-256 ou supérieur pour l'algorithme de signature.")
        print(table)


class HtmlModel:
    def __init__(self, results : Results, filepath: str) -> None:
        self.rep = "./Ressources/rapport html/"
        self.modelFichier = "modele.html"
        self.nomFichier = filepath
        self.results = results
        
    
    @property
    def nomFichier(self) -> str:
        return self._nomFichier
    
    @nomFichier.setter
    def nomFichier(self, value: str) -> None:
        self._nomFichier = value
    


    def creer_rapport_html(self) -> None:

        def creerRegle(regle):
            baliseTr = template_html.new_tag("tr")
            baliseNumero = template_html.new_tag("th")
            baliseTitre = template_html.new_tag("td")
            baliseDescription = template_html.new_tag("td")
            baliseValide = template_html.new_tag("td")
            baliseCritique = template_html.new_tag("td")
            baliseCorrection = template_html.new_tag("td")

            
            test = True
            regle.passed = regle.auditable and test and regle.passed

            couleurRegle = infoTache.get(int(not regle.critical) + 2 * int(regle.passed) + 4 * int(not regle.auditable) + 6 * int(not test), "Erreur")["class"]

            baliseNumero.string = regle.name
            baliseTitre.string = regle.title
            baliseDescription.string = regle.description
            baliseCorrection.string = regle.mitigation
            baliseCritique.string = regle.critical and "✓" or "✕"
            if regle.auditable and test:
                baliseValide.string = regle.passed and "✓" or "✕"
            else:
                baliseValide.string = "-"

            baliseNumero["class"] = couleurRegle
            baliseTitre["class"] = couleurRegle
            baliseDescription["class"] = couleurRegle
            baliseCorrection["class"] = couleurRegle
            baliseValide["class"] = couleurRegle
            baliseCritique["class"] = couleurRegle
            
            baliseTr["class"] = "text-center"

            baliseTr.append(baliseNumero)
            baliseTr.append(baliseTitre)
            baliseTr.append(baliseDescription)
            baliseTr.append(baliseCorrection)
            baliseTr.append(baliseCritique)
            baliseTr.append(baliseValide)

            return baliseTr

        def creerClient(client):
            baliseTr = template_html.new_tag("tr")
            baliseClient = template_html.new_tag("th")
            baliseSupporte = template_html.new_tag("td")

            supporte = client in self.results.supported_clients
            couleurRegle = infoTache.get(2 * int(supporte), "Erreur")["class"]

            baliseClient.string = client
            baliseSupporte.string = supporte and "✓" or "✕"

            baliseClient["class"] = couleurRegle
            baliseSupporte["class"] = couleurRegle
            
            baliseTr["class"] = "text-center"

            baliseTr.append(baliseClient)
            baliseTr.append(baliseSupporte)

            return baliseTr

        def creerDiv(value):
            p = template_html.new_tag("div")
            if type(value) == str:
                p.string = value
            else:
                p.string = str(value)
            return p

        def creerInfoCert(head : str, val: str | list):
            baliseTr = template_html.new_tag("tr")
            baliseHeader = template_html.new_tag("th")
            baliseInfo = template_html.new_tag("td")

            baliseHeader.string = head
            if type(val) == list:
                for value in val:
                    baliseInfo.append(creerDiv(value))
            else:
                baliseInfo.string = val

            
            

            baliseTr.append(baliseHeader)
            baliseTr.append(baliseInfo)

            return baliseTr

        def gradeCouleur(grade_str : str):
            grade_classe = {
                "A+": "text-success",
                "A": "text-success",
                "A-": "text-success",
                "B": "text-yellow",
                "C": "text-yellow",
                "D": "text-warning",
                "E": "text-warning",
            }
            
            return grade_classe.get(grade_str, "text-danger")
        
        def suiteCouleur(cipher : str):
            strong_ciphers = [
                            "TLS_AES_256_GCM_SHA384",
                            "TLS_AES_128_GCM_SHA256",
                            "TLS_AES_128_CCM_SHA256",
                            "TLS_CHACHA20_POLY1305_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
                            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"                           
                        ]
        
            degraded_ciphers = [
                            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_DHE_RSA_WITH_AES_128_CCM",
                            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
                            "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
                            "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
                            "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
                            "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
                            "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
                            "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
                            "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
                            "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
                            "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_DHE_PSK_WITH_AES_256_CCM",
                            "TLS_DHE_PSK_WITH_AES_128_CCM",
                            "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
                            "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
                            "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
                            "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
                            "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
                            "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
                            "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
                            "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
                            "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
                            "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
                            "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"
                        ]

            if cipher in strong_ciphers:
                return "text-success"
            elif cipher in degraded_ciphers:
                return "text-yellow"
            else:
                return "text-danger"
        
        def protocoleCouleur(protocole: str):
            if protocole in ["TLS 1.3"]:
                return "text-success"
            elif protocole not in ["TLS 1.3", "TLS 1.2"]:
                return "text-danger"
            else:
                return ""

        def creerResumeEval(cat : str, pourc: float, note: str, com: str, reco: str):
            baliseTr = template_html.new_tag("tr")
            baliseCategorie = template_html.new_tag("th")
            balisePourcentage = template_html.new_tag("td")
            baliseNote = template_html.new_tag("td")
            baliseCommentaire = template_html.new_tag("td")
            baliseRecommendation = template_html.new_tag("td")

            baliseCategorie.string = cat
            balisePourcentage.string = f"{pourc:.0f}%"
            baliseNote.string = note
            baliseNote["class"] = gradeCouleur(note)
            baliseCommentaire.string = com
            baliseRecommendation.string = reco

            baliseTr.append(baliseCategorie)
            baliseTr.append(balisePourcentage)
            baliseTr.append(baliseNote)
            baliseTr.append(baliseCommentaire)
            baliseTr.append(baliseRecommendation)

            return baliseTr

        with open(self.rep + self.modelFichier, "r") as fichierModele:
            template_html = BeautifulSoup(fichierModele, 'html.parser')
        
        regles = template_html.find("tbody", {"id": "regles"})
        note = template_html.find("td", {"id": "note"})
        clients = template_html.find("tbody", {"id": "clients"})

        infoTache = {}
        infoTache[0] = template_html.find("td", {"id": "echec-critique"})
        infoTache[1] = template_html.find("td", {"id": "echec"})
        infoTache[2] = template_html.find("td", {"id": "succes-critique"})
        infoTache[3] = template_html.find("td", {"id": "succes"})
        infoTache[4] = template_html.find("td", {"id": "non-verifie-critique"})
        infoTache[5] = template_html.find("td", {"id": "non-verifie"})
        # infoTache[6] = template_html.find("td", {"id": "non-teste-critique"})
        # infoTache[7] = template_html.find("td", {"id": "non-teste"})

        test = True
        
        # Règles
        
        cptTache = {}
        for cpt in range(len(infoTache)):
            cptTache[cpt] = 0
        
        regleFailed = []
        reglesSucces = []
        reglesVerif = []
        reglesNotTested = []

        for rule in self.results.rules:
            if not test:
                reglesNotTested.append(rule)
            elif not rule.auditable:
                reglesVerif.append(rule)
            elif not rule.passed:
                regleFailed.append(rule)
            else:
                reglesSucces.append(rule)
            cptTache[int(not rule.critical) + 2 * int(rule.passed) + 4 * int(not rule.auditable) + 6 * int(not test)] += 1
            

        
        for rule in chain(regleFailed, reglesNotTested, reglesSucces, reglesVerif):
            regles.append(creerRegle(rule))
        
                
        for cpt in range(len(infoTache)):
            infoTache[cpt].string = str(cptTache[cpt])
        
        # Clients
        if self.results.client_profiles[0] != '':
            for client in self.results.client_profiles:
                clients.append(creerClient(client))
        else:
            clients.parent.decompose()

        
        
        # Informations connexion TLS
        nomServeur  = template_html.find("td", {"id": "nom-serveur"})
        versionsTLS = template_html.find("td", {"id": "versions-TLS"})
        suitesCrypto = template_html.find("tbody", {"id" : "suites-cryptographique"})
        fichierRegle = template_html.find("td", {"id": "fichier-regle"})
        pourcentageRegle = template_html.find("td", {"id": "pourcentage"})
        noteRegle = template_html.find("td", {"id" : "note"})
        infoCert = template_html.find("tbody", {"id": "info-cert-serveur"})
        infoCertExtensions = template_html.find("tbody", {"id": "info-extensions-serveur"})
        prefServeur = template_html.find("td", {"id": "pref-serveur"})
        resumEval = template_html.find("tbody", {"id": "resume-eval"})
        infoDate = template_html.find("td", {"id": "date"})
        infoHeure = template_html.find("td", {"id": "heure"})
        

        # print(tls_checker.user_args)
        lienSite = template_html.new_tag("a")
        lienSite.string = tls_checker.user_args.host
        lienSite["href"] = "https://" + tls_checker.user_args.host + ":" + str(tls_checker.user_args.port)
        nomServeur.append(lienSite)
        lienRegle = template_html.new_tag("a")
        lienRegle.string = tls_checker.user_args.rules_file
        lienRegle["href"] = "file:///" + os.path.abspath(self.results.rules.repRule + tls_checker.user_args.rules_file)
        fichierRegle.append(lienRegle)
        pourcentageRegle.string = "{:.0f}%".format(self.results.grade_rules)
        noteRegle.string = self.results.grade_rules_str
        noteRegle["class"] = gradeCouleur(self.results.grade_rules_str)
        prefServeur.string = self.results.prefer_server_ciphers and "✓" or "✕"
        prefServeur["class"] = self.results.prefer_server_ciphers and "text-success" or "text-danger"
        infoDate.string = datetime.datetime.today().strftime('%Y-%m-%d')
        infoHeure.string = datetime.datetime.now().strftime("%H:%M:%S")


        for protocole in self.results.protocols:
            div = creerDiv(protocole)
            div["class"] = protocoleCouleur(protocole)
            versionsTLS.append(div)
        
        for suite in self.results.ciphers:
            # tr = template_html.new_tag
            div = creerDiv(suite)
            div["class"] = suiteCouleur(suite)
            suitesCrypto.append(div)

        resumEval.append(creerResumeEval("Taille de la Clé", self.results.grade_key * 100, self.results.grading_letters(self.results.grade_key * 100),
        self.results.comment_key_size(self.results.grade_key), "256 bits ou plus recommandé pour une sécurité optimale."))

        resumEval.append(creerResumeEval("Protocoles", self.results.grade_protocol * 100, self.results.grading_letters(self.results.grade_protocol * 100),
                        self.results.comment_protocol(self.results.grade_protocol), "TLS 1.3 est recommandé pour la meilleure sécurité. TLS 1.2 est également accepté."))
        
        resumEval.append(creerResumeEval("Suites Cryptographiques", self.results.grade_ciphers * 100, self.results.grading_letters(self.results.grade_ciphers * 100),
                        self.results.comment_cipher(self.results.grade_ciphers), "Veillez à utiliser des suites cryptographiques qui sont recommendé ."))
        
        resumEval.append(creerResumeEval("Certificats", self.results.grade_cert, self.results.grading_letters(self.results.grade_cert),
                        self.results.comment_certificate(self.results.grade_cert), "Évitez les certificats auto-signés et utilisez SHA-256 ou supérieur pour l'algorithme de signature."))
        
        # Résumé Notes d'Evaluation

        # Informations Certificat serveur
        infoCert.append(creerInfoCert("Sujet", str(self.results.certs[0].subject['commonName'])))
        infoCert.append(creerInfoCert("Emetteur", str(self.results.certs[0].issuer['commonName'])))
        infoCert.append(creerInfoCert("Emetteur Organistation", str(self.results.certs[0].issuer['organizationName'])))
        infoCert.append(creerInfoCert("Emetteur Pays", str(self.results.certs[0].issuer['countryName'])))
        infoCert.append(creerInfoCert("Valide du", time.strftime("%Y-%m-%d %H:%M:%S", self.results.certs[0].notBefore)))
        infoCert.append(creerInfoCert("Valide jusqu'au", time.strftime("%Y-%m-%d %H:%M:%S", self.results.certs[0].notAfter)))
        infoCert.append(creerInfoCert("Algorithme de Signature", str(self.results.certs[0].sigAlg)))
        infoCert.append(creerInfoCert("Auto-signé", "Oui" if self.results.certs[0].isSelfSigned() else "Non"))

        for key, val in self.results.cert_extensions.items():
            if key  == "subjectAltName":
                infoCertExtensions.append(creerInfoCert("Noms alternatifs du sujet", val.content))
            elif key == "keyUsage":
                infoCertExtensions.append(creerInfoCert("Usages", val.content))
            elif key == "extKeyUsage":
                infoCertExtensions.append(creerInfoCert(key, val.content))
        
        # ajout dépendances bootstrap

        balStyle = template_html.new_tag("style")
        balScript = template_html.new_tag("script")

        balStyle["type"] = "text/css"
        balScript["type"] = "text/javascript"

        bootstrap = "bootstrap-5.3.3-dist/bootstrap"
        with open(self.rep + bootstrap + ".css", 'r') as bootstrapFile:
            balStyle.string = bootstrapFile.read()
        
        with open(self.rep + bootstrap + ".js", 'r') as bootstrapFile:
            balScript.string = bootstrapFile.read()
        
        head = template_html.find("head")

        head.append(balStyle)
        head.append(balScript)

        with open(self.nomFichier, 'w') as fichierDest:
            fichierDest.write(template_html.prettify())    

class TLS_Checker:
    """
    The TLS_Checker class is responsible for retrieving server parameters and collecting useful information about SSL certificates.

    Attributes:
    - server_params (ServerParameters): The connection parameters.
    - user_args (argparse.Namespace): The user arguments.
    - rules (RuleCollection): The collection of rules to be tested against server's parameters.
    - results (Results): The results of the TLS checking.

    Methods:
    - run(): Connects to the server and retrieves server parameters.
    - init_client_hello(profile: TLSClientProfile, ciphers: list[int], version: int, curves: list[str]) -> TLSClientHello|TLS13ClientHello: Initializes the ClientHello packet.
    - init_automaton(client_hello: TLSClientHello|TLS13ClientHello, version: int) -> TLSCheckerAutomaton: Initializes the client automaton.
    - get_supported_protocols(): Retrieves the supported server protocols.
    - get_supported_ciphers(): Retrieves the supported server ciphers.
    - get_supported_extensions(): Retrieves the supported bad server extensions.
    - get_server_params(): Retrieves the connection parameters.
    - get_cipher_preference(): Retrieves the server cipher order preference (server or client).
    - test_client_profile(client: str= ""): Tests the client profile.
    - test_rules(): Tests the rules against the server parameters.
    - get_args(json_args={}): Sets argparse options.
    """
    class TLSCheckerConnectionError(Exception):
        """An error occurred while trying to establish a TLS connection to the server."""
        pass
    class TLSCheckerCipherError(Exception):
        """An error occurred while retrieving the server ciphers."""
        pass

    def __init__(self, user_args: argparse.Namespace) -> None:
        """Initializes the TLS_Checker object.
        Args:
        - user_args (argparse.Namespace): The user arguments.
        """
        self.server_params:ServerParameters = ServerParameters()
        self.user_args = user_args
        self.rules:RuleCollection
        self.results:Results

    @property
    def server_params(self) -> ServerParameters:
        """The server parameters."""
        return self._server_params

    @server_params.setter
    def server_params(self, value):
        self._server_params = value
        
    @property
    def rules(self) -> RuleCollection:
        """A RuleCollection object containing the rules to be tested against server's parameters."""
        return self._rules
    
    @rules.setter
    def rules(self, value):
        self._rules = value

    @property
    def results(self) -> Results:
        """The results of the TLS checking."""
        return self._results
    
    @results.setter
    def results(self, value):
        self._results = value

    def run(self) :
        """
        Connects to the server and retrieves server parameters. Performs the tests and print the results.
        """
        console = Console()
        console.print("\n\n")
        explanation = Text(
        "https://github.com/EdouardRouch/tls_checker\n\n" \
        "This program is a free software. Distribution and modification are allowed under the terms of the GPLv3 license.\n\n" \
        "This program comes with ABSOLUTELY NO WARRANTY.\nUSE IT AT YOUR OWN RISK!", justify="center")
        greetings = Panel(explanation, title="[bold]tls_checker.py v1.0.0", width=75, border_style="green3", padding=(1, 3))
        console.print(greetings)
        console.print("\n\n")


        try:
            with console.status("Starting TLS_checker", spinner="dots") as spinner:
                spinner.update("Testing server reachability...")
                socket.getaddrinfo(self.user_args.host, self.user_args.port)
                console.print(":heavy_check_mark: [white]Server reachable proceeding to parameter retrieval", style="green")

                spinner.update("Retrieving supported_protocols...")
                self.server_params.protocols = self.get_supported_protocols()
                if len(self.server_params.protocols) == 0:
                    raise self.TLSCheckerConnectionError
                console.print(":heavy_check_mark: [white]Supported protocols retrieved", style="green")

                spinner.update("Retrieving supported ciphers")
                self.server_params.ciphers = self.get_supported_ciphers()
                if len(self.server_params.ciphers) == 0:
                    raise self.TLSCheckerCipherError
                console.print(":heavy_check_mark: [white]Supported ciphers retrieved", style="green")

                spinner.update("Retrieving supported curves")
                self.server_params.curves = self.get_supported_curves()
                console.print(":heavy_check_mark: [white]Supported curves retrieved", style="green")

                spinner.update("Retrieving supported TLS extensions...")
                self.server_params.extensions = self.get_supported_extensions()
                console.print(":heavy_check_mark: [white]Supported TLS extensions retrieved", style="green")

                spinner.update("Retrieving server parameters...")
                self.set_server_parameters()
                self.server_params.are_all_versions_certs_different = self.are_all_versions_certs_different()
                self.server_params.ciphers = self.get_cipher_order_preference()
                console.print(":heavy_check_mark: [white]Server parameters retrieved", style="green")

                if self.user_args.client_profiles != ['']:
                    spinner.update("Testing client profiles...")
                    for client in self.user_args.client_profiles:
                        if self.test_client_profile(client):
                            self.server_params.supported_clients.append(client)
                    console.print(":heavy_check_mark: [white]Client profiles tested", style="green")

                if self.user_args.rules_file:
                    spinner.update(f'Analyzing server parameters with {self.user_args.rules_file}...')
                    self.rules = self.test_rules()
                    console.print(":heavy_check_mark: [white]Server parameters analyzed", style="green")

            if self.user_args.rules_file:
                results = Results(self.server_params, self.rules, self.user_args)         
                if self.user_args.summary_true:
                    results.print_server_parameters()
                    results.grading()
                    results.print_cert_value()
                    results.print_grading_rules()
                    results.print_grading_summary()
                else: 
                    results.print_analysed_rules()
                    results.print_non_auditable_rules()
                    results.print_server_parameters()
                    results.grading()
                    results.print_cert_value()
                    results.print_grading_rules()
                    results.print_grading_summary()
                if self.user_args.client_profiles[0] != '':
                    results.print_supported_clients()
                if self.user_args.html_file:
                    rapportHtml = HtmlModel(results, self.user_args.html_file)
                    rapportHtml.creer_rapport_html()
                    console.print(f':heavy_check_mark: [white]HTML report generated at {self.user_args.html_file}', style="green")
                if self.user_args.json_file:
                    with open(self.user_args.json_file, 'w') as json_file:
                        json_file.write(jsonpickle.encode(results, indent=1))
                    console.print(f':heavy_check_mark: [white]JSON report generated at {self.user_args.json_file}', style="green")
            else:
                results = Results(self.server_params, None, self.user_args)
                results.print_server_parameters()
                results.print_cert_value()
                results.grading_without_rules()
                results.print_grading_summary()
                if self.user_args.client_profiles[0] != '':
                    results.print_supported_clients()

        except socket.gaierror:
            console.print(":cross_mark: Server unreachable, check hostname or port", style="red")
            exit(1)
        except KeyboardInterrupt:
            console.print(":cross_mark: Operation cancelled", style="red")
            exit(1)
        except self.TLSCheckerConnectionError:
            console.print(":cross_mark: No TLS connection to the server could be established", style="red")
            exit(1)
        except self.TLSCheckerCipherError:
            console.print(":cross_mark: No TLS ciphers supported by the server", style="red")
            exit(1)
        except :
            console.print(":cross_mark: An error occured!\n", style="red")
            logging.exception('')
            exit(1)
        
    def get_supported_protocols(self) -> list[int]:
        """
        Retrieves the supported server protocols.

        Returns:
        - list[int]: The supported server protocols.
        """
        supported_protocols = []
        for id in _tls_version_options.values():
            if id <= 772:
                ch = self.init_client_hello(version=id)
                automaton = self.init_automaton(client_hello=ch, version=id)
                setattr(automaton, 'supported_protocols', supported_protocols)
                try:
                    automaton.run()
                    automaton.stop()
                except:
                    continue
        return supported_protocols

    def get_supported_ciphers(self) -> list[int]:
        """
        Retrieves the supported server ciphers.

        Returns:
        - list[int]: The supported server ciphers.
        """
        supported_ciphers = []
        highest_legacy_protocol = self.server_params.highest_legacy_protocol
        for cipher in _tls_cipher_suites.keys():
            if cipher <= 65535:
                if cipher >= 0x1301 and cipher <= 0x1305:
                    ch = self.init_client_hello(version=772, ciphers=[cipher])
                    automaton = self.init_automaton(client_hello=ch, version=772)
                else :
                    if highest_legacy_protocol == None: continue
                    ch = self.init_client_hello(version=highest_legacy_protocol, ciphers=[cipher])
                    automaton = self.init_automaton(client_hello=ch, version=highest_legacy_protocol)
                setattr(automaton, 'supported_ciphers', supported_ciphers)
                try :
                    automaton.run()
                    automaton.stop()
                except:
                    continue
        return supported_ciphers

    def get_cipher_order_preference(self) -> list[int]:
        """
        Retrieves the server cipher order preference (server or client).

        Returns:
        - list[int]: The server ciphers in server's preference order.
        """
        if not self.server_params.ciphers:
            return
        version = self.server_params.highest_legacy_protocol
        ch = self.init_client_hello(version=version)
        cipher_prefer = []
        for i in range(2):
            automaton = self.init_automaton(client_hello=ch, version=version)
            setattr(automaton, 'cipher_prefer', cipher_prefer)
            automaton.run()
            automaton.stop()
            ch.ciphers = ch.ciphers[1:] + ch.ciphers[:1]
        if len(cipher_prefer) < 2:
            return self.server_params.ciphers
        elif cipher_prefer[0] != cipher_prefer[1]:
            return self.server_params.ciphers
        else:
            self.server_params.prefer_server_ciphers_order = True
            ciphers = self.server_params.ciphers.copy()
            ciphers.remove(cipher_prefer[0])
            cipher_prefer.pop()
            cipher_prefer_tls13 = []
            for i in range(len(self.server_params.ciphers)-1):
                if ciphers[0] in [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]:
                    version = 772
                ch = self.init_client_hello(version=version, ciphers=ciphers)
                automaton = self.init_automaton(client_hello=ch, version=version)
                setattr(automaton, 'cipher_prefer', cipher_prefer)
                automaton.run()
                automaton.stop()
                ciphers.remove(cipher_prefer[-1])
                if cipher_prefer[-1] in [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]:
                    cipher_prefer_tls13.append(cipher_prefer[-1])
                    cipher_prefer.pop()
            return cipher_prefer_tls13 + cipher_prefer
            
            

    def get_supported_curves(self) -> list[str]:
        """
        Retrieves the supported server curves.

        Returns:
        - list[str]: The supported server curves.
        """
        supported_curves = []
        version = self.server_params.highest_legacy_protocol
        if version == None:
            curves = ["secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1","x25519","x448"]
            ciphers = None
        else :
            curves = _tls_named_curves.values()
            ciphers = []
            for c in self.server_params.ciphers:
                if "ECDHE" in _tls_cipher_suites[c]:
                    ciphers.append(c)
                    break
        for curve in curves :
            ch = self.init_client_hello(version=version, groups=[curve], ciphers=ciphers)
            automaton = self.init_automaton(client_hello=ch, version=version)
            setattr(automaton, 'supported_curves', supported_curves)
            try:
                automaton.run()
                automaton.stop()
            except:
                pass
        return supported_curves
    
    def set_server_parameters(self):
        """
        Retrieves and sets the server parameters in server_params attribute.
        """
        if  not self.server_params.ciphers or \
            not self.server_params.protocols:
            return
        version = self.server_params.highest_legacy_protocol
        ch = self.init_client_hello(ciphers=self.server_params.ciphers, version=version)
        automaton = self.init_automaton(client_hello=ch, version=version)
        setattr(automaton, 'server_params', self.server_params)
        automaton.run()
        automaton.stop()

    def get_supported_extensions(self) -> list[str]:
        """
        Retrieves the supported server extensions.

        Returns:
        - list[str]: The supported server extensions.
        """
        bad_ext = [ None,
                    TLS_Ext_MaxFragLen(),
                    TLS_Ext_ClientCertURL(),
                    TLS_Ext_TruncatedHMAC(),
                    TLS_Ext_ClientAuthz(),
                    TLS_Ext_ServerAuthz(),
                    TLS_Ext_ServerCertType(ctype=0),
                    TLS_Ext_ClientCertType(ctypes=0),
                    TLS_Ext_SupportedPointFormat(),
                    TLS_Ext_Heartbeat(heartbeat_mode=1),
                    TLS_Ext_SessionTicket(),
                    TLS_Ext_ALPN(protocols=[ProtocolName(protocol="http/1.1"), ProtocolName(protocol="h2")]),
                    TLS_Ext_CSR(stype=1, req=[OCSPStatusRequest()]),
                    TLS_Ext_TrustedCAInd(),
                    TLS_Ext_UserMapping(),
                    TLS_Ext_Padding(),
                    TLS_Ext_RecordSizeLimit(record_size_limit=16384)
        ]
        supported_extensions = []
        version = self.server_params.highest_legacy_protocol
        for ext in bad_ext:
            ch = self.init_client_hello(version=version)
            if ext: ch.ext += ext
            automaton = self.init_automaton(client_hello=ch, version=version)
            setattr(automaton, 'supported_extensions', supported_extensions)
            setattr(automaton, 'server_params', self.server_params)
            try :  
                automaton.run()
                automaton.stop()
            except :
                pass

        if self.server_params.highest_protocol == 772:
            ch = self.init_client_hello(version=772)
            tls13_bad_ext = [   None, 
                                TLS_Ext_EarlyDataIndication(),
                                TLS_Ext_Cookie(),
                                TLS_Ext_PSKKeyExchangeModes(kxmodes=1)
                            ]
            for ext in tls13_bad_ext:
                if ext: ch.ext += ext
                automaton = self.init_automaton(client_hello=ch, version=772)
                setattr(automaton, 'supported_extensions', supported_extensions)
                try:
                    automaton.run()
                    automaton.stop()
                except:
                    pass
        return supported_extensions

    def are_all_versions_certs_different(self) -> bool:
        comp_versions_certs = []
        for version in self.server_params.protocols:
            ch = self.init_client_hello(version=version)
            automaton = self.init_automaton(client_hello=ch, version=version)
            setattr(automaton, 'comp_versions_certs', comp_versions_certs)
            automaton.run()
            automaton.stop()
        return len(comp_versions_certs) == len(self.server_params.protocols)
    
    def test_client_profile(self, client: str= "") -> bool:
        """
        Tests the client profile.

        Args:
        - client (str): The client to test.

        Returns:
        - bool: True if the client is supported, False otherwise.    
        """
        if not client: return
        client_profile = TLSClientProfile(f'Ressources/clients/{client}.json')
        ch = self.init_client_hello(profile=client_profile)
        automaton = self.init_automaton(client_hello=ch, version=client_profile.highest_protocol)
        is_client_supported = [False]
        setattr(automaton, 'is_client_supported', is_client_supported)
        try:
            automaton.run()
            automaton.stop()
        except:
            pass
        return is_client_supported[0]

    def init_client_hello(self, profile: TLSClientProfile = None, 
                                version:int=None, 
                                ciphers:list=None,
                                groups:list=None, 
                                ext:list[TLS_Ext_Unknown]=None) -> TLSClientHello|TLS13ClientHello:
        """
        Initializes the ClientHello packet.

        Args:
        profile (str): A client profile to generate a client hello for.
        version (int): The TLS version to use.
        ciphers (list[int]): The list of ciphers to use.
        groups (list[str]): The list of Diffie-Hellman groups to use.
        ext (list[TLS_Ext_Unknown]): The list of extensions to use.

        Returns:
            TLSClientHello or TLS13ClientHello: The initialized ClientHello packet.
        """
        if profile:
            if profile.highest_protocol == "772":
                pkt = TLS13ClientHello()
            else:
                pkt = TLSClientHello()
            ciphers = []
            for k,v in _tls_cipher_suites.items():
                if k <= 65535 :
                    if v in profile.suite_names:
                        ciphers.append(k)
            pkt.ciphers = ciphers
            if profile.supports_compression:
                pkt.compression_methods = [1]
            groups = [c for c in profile.elliptic_curves_names]
        else:
            if not version :
                version = self.server_params.highest_protocol
            if version == 772:
                pkt = TLS13ClientHello()
                if ciphers != None: pkt.ciphers = ciphers.copy()
                else :
                    if self.server_params.ciphers:
                        pkt.ciphers = self.server_params.ciphers.copy()
                    else : pkt.ciphers = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]
            else :
                pkt = TLSClientHello()
                if ciphers != None: pkt.ciphers = ciphers.copy()
                else: 
                    if self.server_params.ciphers:
                        pkt.ciphers = self.server_params.ciphers.copy()

        if ext != None: pkt.ext = ext.copy()
        else:
            if groups == None :
                groups = ["secp256r1", "secp384r1", "secp521r1", 
                        "x448", "x25519", 
                        "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
            pkt.ext = [ TLS_Ext_SignatureAlgorithms(sig_algs=[  'sha256+rsaepss', 'sha512+rsaepss', 'sha384+rsaepss',
                                                                'sha256+rsa', 'sha512+rsa', 'sha384+rsa', 
                                                                'sha256+ecdsa', 'sha512+ecdsa', 'sha384+ecdsa']),
                        TLS_Ext_ServerName(servernames=[ServerName(servername=self.user_args.host)]),
                        TLS_Ext_SupportedGroups(groups=groups)]
            if version == 772:
                key_share_entries = [KeyShareEntry(group=c) for c in groups]
                pkt.ext +=  TLS_Ext_KeyShare_CH(client_shares=key_share_entries)
            else:
                pkt.ext += [TLS_Ext_EncryptThenMAC(),
                            TLS_Ext_SupportedPointFormat(),
                            TLS_Ext_ExtendedMasterSecret(),
                            TLS_Ext_RenegotiationInfo()
                ]
        pkt.server_name = self.user_args.host
        return pkt
    
    def init_automaton(self, client_hello:TLSClientHello|TLS13ClientHello, version:int=None) -> TLSCheckerAutomaton:
        """
        Initializes the TLSCheckerAutomaton. 

        If the version is not specified, the highest protocol version supported by the server is used.

        Args:
        - client_hello : The ClientHello packet.
        - version : The TLS version to use.
        
        Returns:
        - TLSCheckerAutomaton: The initialized TLSCheckerAutomaton.
        """
        if not version:
            version = self.server_params.highest_protocol
        version_str = list(_tls_version_options.keys())[list(_tls_version_options.values()).index(version)]
        automaton = TLSCheckerAutomaton(server=self.user_args.host, dport=self.user_args.port, 
                                         server_name=self.user_args.host, client_hello=client_hello,
                                         version=version_str, verbose=False)
        return automaton

    def test_rules(self) -> RuleCollection:
        """
        Tests the rules against the server parameters.
        
        Returns:
        - RuleCollection: The collection of rules.
        """
        rules = RuleCollection(self.user_args.rules_file)
        for rule in rules:
            if rule.auditable:
                rule.passed = self.recursive_rule_test(rule.requirements)
        return rules

    def recursive_rule_test(self, req:dict) -> bool:
        """
        Recursively tests the rules against the server parameters.
        
        Args:
        - req (dict): The requirements to test.

        Returns:
        - bool: True if the requirements are met, False otherwise.
        """
        key = list(req.keys())[0]
        match key:
            case 'and':
                if len(req['and']) == 0:
                    return True
                e=req['and'][0]
                req['and'] = req['and'][1:]
                return self.recursive_rule_test(e) and self.recursive_rule_test(req)
            case 'or':
                if len(req['or']) == 0:
                    return False
                e=req['or'][0]
                req['or'] = req['or'][1:]
                return self.recursive_rule_test(e) or self.recursive_rule_test(req)
            case 'not':
                return not self.recursive_rule_test(req['not'])
            case 'greater':
                k, v = req['greater'].popitem()
                return self.server_params.get(k) > v
            case 'greater_or_equal':
                k, v = req['greater_or_equal'].popitem()
                return self.server_params.get(k) >= v
            case 'lower_or_equal':
                k, v = req['lower_or_equal'].popitem()
                return self.server_params.get(k) <= v
            case 'param_equal':
                k, v = req['param_equal'].popitem()
                return self.server_params.get(k) == v
            case 'endswith':
                k, v = req['endswith'].popitem()
                return self.server_params.get(k).endswith(v)
            case 'a_in_b':
                k, v = req['a_in_b'].popitem()
                k = self.server_params.get(k)
                if type(k) == list and type(v) == list:
                    return set(k).issubset(v)
                if type(k) == str and type(v) == str:
                    return k.upper() in v.upper()
                return k in v
            case 'b_in_a':
                k, v  = req['b_in_a'].popitem()
                k = self.server_params.get(k)
                if type(k) == list and type(v) == list:
                    return set(v).issubset(k)
                if type(k) == str and type(v) == str:
                    return v.upper() in k.upper()
                return v in k
            case 'len':
                operand = req['len'].pop('operand', None)
                k, v = req['len'].popitem()
                k = self.server_params.get(k, [])
                match operand:
                    case ">":
                        return len(k) > v
                    case "<":
                        return len(k) < v
                    case ">=":
                        return len(k) >= v
                    case "<=":
                        return len(k) <= v
                    case _:
                        return len(k) == v
            case _ :
                k, v  = req.popitem()
                return self.server_params.get(k) == v
            
def get_args(json_args={}):
    """
    Sets argparse options.

    Args:
        json_args (dict): JSON arguments.

    Returns:
        argparse.Namespace: The user arguments.
    """
    parser = ArgumentParser(prog='tls_checker.py',
                            description="""Collects useful information about the given host's TLS server and compares them to ANSSI TLS recommandations.""",
                            epilog="""Authors: Alexis CYPRIEN, Léo BIREBENT, Rania HADDAOUI, Amina LARABI, Édouard ROUCH""") 
    

    if len(json_args) > 0:
        args = parser.parse_args()
        setattr(args, 'json_file', '')
        setattr(args, 'csv_enabled', False)
        setattr(args, 'html_file', "")
        setattr(args, 'client_profiles', json_args['client_profiles'])
        setattr(args, 'host', json_args['host'])
        setattr(args, 'rules_file', json_args['rules_file'])
        setattr(args, 'port', json_args['port'])
        return args

    parser.add_argument('-H', '--host', dest='host',
                        required=True, help='Host to connect to')
    parser.add_argument('-p', '--port', dest='port', required=False, default=443, help='Port to connect to, default is 443', type=int)
    parser.add_argument('-c', '--profile', dest='client_profiles',
                        required=False, default='',
                        help='Comma separated list of client profiles to test for connection, "all" to test all profiles')
    parser.add_argument('-r', '--rules', dest='rules_file', required=False, default='', 
                            help='JSON file containing the rules to test')
    parser.add_argument('-j', '--json', dest='json_file', default='',
                        help='Generate a JSON output at the given path')
    parser.add_argument('-s', '--summary', dest='summary_true',
                        action='store_true', default=False,
                        help='Enable summary output only')
    parser.add_argument('-x', '--html', dest='html_file', default='',
                        help='Generate a HTML report at the given path')

    args = parser.parse_args()

    if args.client_profiles.upper().startswith("ALL"):
        args.client_profiles = [f.split('.')[0] for f in os.listdir('Ressources/clients') if f.endswith('.json')]
    else :
        args.client_profiles = args.client_profiles.split(',')
    
    if args.rules_file:
        if not args.rules_file.endswith('.json'):
            args.rules_file += '.json'
        if not os.path.exists(f'./Ressources/rules/{args.rules_file}'):
            print(f"Error: File '{args.rules_file}' does not exist. Did you mean to use the default rules file 'ANSSI_TLS_v1-2.json'?")
            exit(1)       
    
    if args.html_file:
        if not args.html_file.endswith('.html'):
            args.html_file += '.html'

    return args

if __name__ == "__main__":
    tls_checker = TLS_Checker(get_args())
    tls_checker.run()