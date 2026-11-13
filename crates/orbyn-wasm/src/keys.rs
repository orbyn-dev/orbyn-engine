//! Zones and zone keys at the JavaScript boundary: the token check, the first key, rotation, and
//! the envelopes to trusted devices and to the account's service key.

use super::*;

#[wasm_bindgen]
impl SyncEngine {
    /// Compares one `ZoneList` page with this device; returns `{stale, next}`.
    #[wasm_bindgen(js_name = checkZones)]
    pub fn check_zones(&self, zones_json: &str) -> Result<String> {
        let page: wire::ZoneList = parse(zones_json)?;
        to_json(&self.engine.check_zones(&page))
    }

    /// Makes the zone's first key; returns its id.
    #[wasm_bindgen(js_name = createZoneKey)]
    pub fn create_zone_key(&mut self, zone: &str) -> Result<String> {
        Ok(self.engine.create_zone_key(zone)?)
    }

    /// Replaces the zone's current key with a new one signed by this device;
    /// returns its id. Send it with `envelopesFor`.
    #[wasm_bindgen(js_name = rotateZoneKey)]
    pub fn rotate_zone_key(&mut self, zone: &str) -> Result<String> {
        Ok(self.engine.rotate_zone_key(zone)?)
    }

    /// A `PutKeyEnvelopes` sealing every key of the zone to each device of
    /// `devices_json` (a `DeviceList`) this device verifies, other than itself.
    /// When the engine holds a service key it verified with `verifyServiceKey`,
    /// every key is also sealed to that key for the escrow; with none verified
    /// the device envelopes are unchanged and `service_envelopes` is absent.
    #[wasm_bindgen(js_name = envelopesFor)]
    pub fn envelopes_for(&mut self, zone: &str, devices_json: &str) -> Result<String> {
        let devices: wire::DeviceList = parse(devices_json)?;
        let service_envelopes = if self.engine.has_verified_service_key() {
            Some(self.engine.service_envelopes_for(zone)?)
        } else {
            None
        };
        to_json(&wire::PutKeyEnvelopes {
            envelopes: self.engine.envelopes_for(zone, &devices)?,
            service_envelopes,
        })
    }

    /// The `NewServiceEnvelope`s of every key of the zone, for the pairs `GET
    /// /v1/keychain/service-missing` lists: each key sealed to the account's
    /// service key this engine verified with `verifyServiceKey`. With nothing
    /// verified it throws `service_key_not_verified` instead of sealing.
    #[wasm_bindgen(js_name = serviceEnvelopesFor)]
    pub fn service_envelopes_for(&self, zone: &str) -> Result<String> {
        to_json(&self.engine.service_envelopes_for(zone)?)
    }
}
