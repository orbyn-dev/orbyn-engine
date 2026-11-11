-- Which Orbyn app a device is (planner or engineering), when the device said so. The device's own
-- signature covers it (orbyn/device-register/v2 and orbyn/device-login/v2), so the server only
-- stores what the device claimed with its key. Existing devices have none.
ALTER TABLE devices ADD COLUMN app text CHECK (app IN ('planner', 'engineering'));
ALTER TABLE pending_signups ADD COLUMN device_app text CHECK (device_app IN ('planner', 'engineering'));
