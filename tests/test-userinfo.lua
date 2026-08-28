local script = tostring(arg[0] or "")
local package_root = script:match("^(.*)/src/tests/[^/]+$")
assert(package_root, "run this test through its repository path")

local userinfo = dofile(package_root .. "/files/natflow-userinfo.lua")

local function u16(value, le)
	local lo = value % 256
	local hi = math.floor(value / 256) % 256
	return le and string.char(lo, hi) or string.char(hi, lo)
end

local function u32(value, le)
	local bytes = {}
	for i = 1, 4 do
		bytes[i] = value % 256
		value = math.floor(value / 256)
	end
	if le then
		return string.char(bytes[1], bytes[2], bytes[3], bytes[4])
	end
	return string.char(bytes[4], bytes[3], bytes[2], bytes[1])
end

local function u64(value, le)
	local bytes = {}
	for i = 1, 8 do
		bytes[i] = value % 256
		value = math.floor(value / 256)
	end
	if le then
		return string.char(unpack(bytes))
	end
	local reversed = {}
	for i = 1, 8 do
		reversed[i] = bytes[9 - i]
	end
	return string.char(unpack(reversed))
end

local function fixed(value, size)
	assert(#value <= size)
	return value .. string.rep("\0", size - #value)
end

local function record(le, family, ip, mac, ifname)
	return table.concat({
		u16(3, le),
		u16(102, le),
		u16(102, le),
		u16(family, le),
		u32(0x12345678, le),
		fixed(ip, 16),
		mac,
		string.char(2, 3),
		u16(513, le),
		string.rep("\255", 8),
		u64(4294967297, le),
		u64(3, le),
		u64(4, le),
		u32(5, le),
		u32(6, le),
		u32(7, le),
		u32(8, le),
		fixed(ifname, 16),
	})
end

local mac = string.char(0x00, 0x11, 0x22, 0xaa, 0xbb, 0xff)
local ipv4 = string.char(192, 0, 2, 10)
local event = assert(userinfo.parse_binary(record(true, userinfo.AF_INET, ipv4, mac, "br-lan")))
assert(event.family == "ipv4")
assert(event.ipaddr == "192.0.2.10")
assert(event.macaddr == "00:11:22:AA:BB:FF")
assert(event.idle_time == 0x12345678)
assert(event.auth_rule_id == 513)
assert(event.rx_packets == "18446744073709551615")
assert(event.rx_bytes == "4294967297")
assert(event.ifname == "br-lan")

local ipv6 = string.char(
	0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 1)
event = assert(userinfo.parse_binary(record(false, userinfo.AF_INET6, ipv6, mac, "lan0")))
assert(event.family == "ipv6")
assert(event.ipaddr == "2001:db8:0:0:0:0:0:1")
assert(event.rx_bytes == "4294967297")

event = assert(userinfo.parse_text(
	"2001:db8::1,00:11:22:aa:bb:ff,0x2,0x3,513,9,10:20,30:40,5:6,7:8,br-lan"))
assert(event.family == "ipv6")
assert(event.macaddr == "00:11:22:AA:BB:FF")
assert(event.auth_type == 2 and event.auth_status == 3)
assert(event.tx_bytes == "40" and event.ifname == "br-lan")

local env = userinfo.environment(event, "update")
assert(env.ACTION == "update" and env.USERINFO_VERSION == "3")
assert(env.FAMILY == "ipv6" and env.IPADDR == "2001:db8::1")
assert(env.MACADDR == "00:11:22:AA:BB:FF")
assert(env.IFNAME == "br-lan" and env.DEVICE == "br-lan")
assert(env.RX_PACKETS == "10" and env.TX_BYTES == "40")

env = userinfo.environment(nil, "start")
assert(env.ACTION == "start" and env.USERINFO_VERSION == "3")
assert(env.IPADDR == nil)

assert(not userinfo.parse_binary("short"))
assert(not userinfo.parse_binary(string.rep("\0", userinfo.EVENT_SIZE)))
assert(not userinfo.parse_text("invalid"))

print("userinfo parser tests: PASS")
