#
#  GoogleFindMyTools - Traccar extension
#  Extends NovaApi/ExecuteAction/LocateTracker/location_request.py
#
#  get_location_data_for_device_extended reproduit la logique de
#  get_location_data_for_device mais retourne une liste de dicts de locations
#  au lieu d'appeler decrypt_location_response_locations (effet de bord print-only).
#

import hashlib
import threading
import time

from Auth.fcm_receiver import FcmReceiver

# FcmReceiver is a singleton with a single event loop.
# Concurrent calls to register_for_location_updates crash with AssertionError
# ("self._self_reading_future is None") on Windows asyncio.
# This lock serialises all location requests.
_location_request_lock = threading.Lock()
from NovaApi.ExecuteAction.LocateTracker.decrypt_locations import (
    retrieve_identity_key,
    is_mcu_tracker,
)
from NovaApi.ExecuteAction.LocateTracker.location_request import create_location_request
from NovaApi.nova_request import nova_request
from NovaApi.scopes import NOVA_ACTION_API_SCOPE
from NovaApi.util import generate_random_uuid
from FMDNCrypto.foreign_tracker_cryptor import decrypt
from KeyBackup.cloud_key_decryptor import decrypt_aes_gcm
from ProtoDecoders import DeviceUpdate_pb2, Common_pb2
from ProtoDecoders.decoder import parse_device_update_protobuf


def _parse_locations(device_update_protobuf) -> list:
    """
    Réplique la logique de déchiffrement de decrypt_location_response_locations
    mais retourne une liste de dicts au lieu d'afficher les résultats.

    Chaque dict a l'une des deux formes suivantes :

    Geo location :
        {
            'latitude':      float,
            'longitude':     float,
            'altitude':      float,
            'time':          int,    # Unix timestamp
            'accuracy':      float,
            'status':        int,
            'is_own_report': bool,
        }

    Semantic location :
        {
            'time':          int,
            'status':        int,
            'semantic_name': str,
        }
    """
    device_registration = device_update_protobuf.deviceMetadata.information.deviceRegistration
    identity_key = retrieve_identity_key(device_registration)
    locations_proto = (
        device_update_protobuf
        .deviceMetadata.information
        .locationInformation.reports
        .recentLocationAndNetworkLocations
    )
    is_mcu = is_mcu_tracker(device_registration)

    network_locations      = list(locations_proto.networkLocations)
    network_locations_time = list(locations_proto.networkLocationTimestamps)

    if locations_proto.HasField("recentLocation"):
        network_locations.append(locations_proto.recentLocation)
        network_locations_time.append(locations_proto.recentLocationTimestamp)

    results = []
    for loc, ts in zip(network_locations, network_locations_time):

        if loc.status == Common_pb2.Status.SEMANTIC:
            results.append({
                'time':          int(ts.seconds),
                'status':        int(loc.status),
                'semantic_name': loc.semanticLocation.locationName,
            })
        else:
            encrypted_location = loc.geoLocation.encryptedReport.encryptedLocation
            public_key_random  = loc.geoLocation.encryptedReport.publicKeyRandom

            if public_key_random == b"":
                identity_key_hash  = hashlib.sha256(identity_key).digest()
                decrypted_location = decrypt_aes_gcm(identity_key_hash, encrypted_location)
            else:
                time_offset        = 0 if is_mcu else loc.geoLocation.deviceTimeOffset
                decrypted_location = decrypt(identity_key, encrypted_location, public_key_random, time_offset)

            proto_loc = DeviceUpdate_pb2.Location()
            proto_loc.ParseFromString(decrypted_location)

            results.append({
                'latitude':      proto_loc.latitude  / 1e7,
                'longitude':     proto_loc.longitude / 1e7,
                'altitude':      proto_loc.altitude,
                'time':          int(ts.seconds),
                'accuracy':      loc.geoLocation.accuracy,
                'status':        int(loc.status),
                'is_own_report': loc.geoLocation.encryptedReport.isOwnReport,
            })

    return results


def get_location_data_for_device_extended(canonic_device_id: str, name: str = "Device") -> list:
    """
    Même logique que get_location_data_for_device mais retourne les locations
    déchiffrées sous forme de liste de dicts au lieu de les afficher.

    Args:
        canonic_device_id: Identifiant canonique du device.
        name:              Label utilisé dans les logs.

    Returns:
        Liste de dicts de locations (vide si aucune location disponible).
    """
    with _location_request_lock:
        print(f"[LocationRequest] Requesting location data for {name}...")

        result       = None
        request_uuid = generate_random_uuid()

        def handle_location_response(response):
            nonlocal result
            device_update = parse_device_update_protobuf(response)
            if device_update.fcmMetadata.requestUuid == request_uuid:
                print("[LocationRequest] Location request successful.")
                result = parse_device_update_protobuf(response)

        fcm_token   = FcmReceiver().register_for_location_updates(handle_location_response)
        hex_payload = create_location_request(canonic_device_id, fcm_token, request_uuid)
        nova_request(NOVA_ACTION_API_SCOPE, hex_payload)

        while result is None:
            time.sleep(0.1)

        return _parse_locations(result)
