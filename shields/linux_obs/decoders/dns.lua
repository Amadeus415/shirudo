local function ipv4(value)
	local n = tonumber(value) or 0
	return string.format("%d.%d.%d.%d", n % 256,
		math.floor(n / 256) % 256, math.floor(n / 65536) % 256,
		math.floor(n / 16777216) % 256)
end

local function ipv6(a, b, c, d)
	local words = {}
	for _, value in ipairs({a, b, c, d}) do
		local n = tonumber(value) or 0
		words[#words + 1] = string.format("%02x%02x", n % 256,
			math.floor(n / 256) % 256)
		words[#words + 1] = string.format("%02x%02x",
			math.floor(n / 65536) % 256,
			math.floor(n / 16777216) % 256)
	end
	return table.concat(words, ":")
end

local function address(record)
	if record:u8(7) == 2 then
		return ipv4(record:u32(8))
	end
	return ipv6(record:u32(12), record:u32(16), record:u32(20),
		record:u32(24))
end

local name_bytes = 256
local name_size = 16 + name_bytes
local name_slots = 4
local names_offset = 48
local uid_offset = names_offset + name_slots * name_size
local record_size = uid_offset + 16

local function dirty_records(input, slot_size)
	local slots = shirudo.fixed_records(input.data.pages, slot_size)
	local records = {}
	for _, page in ipairs(input.data.pages) do
		local count = math.floor(page.bytes / slot_size)
		for i = 1, count - 1 do
			local record = slots[page.cursor + i + 1]
			if record and record:u8(6) ~= 0 then
				local names = {}
				for name_index = 0, name_slots - 1 do
					local base = names_offset + name_index * name_size
					if tonumber(record:u64(base)) > 0 then
						names[#names + 1] = {
							name = record:cstring(base + 16, name_bytes),
							seen_count = record:u64(base),
							last_seen_ns = record:u64(base + 8),
						}
					end
				end
				records[#records + 1] = {
					entry_index = record:u32(0),
					executable = {
						dev = record:u32(uid_offset),
						ino = record:u64(uid_offset + 8),
					},
					family = record:u8(7),
					address = address(record),
					names = names,
					total_seen = record:u64(32),
					last_seen_ns = record:u64(40),
				}
			end
		end
	end
	return records
end

function decode(input)
	return {
		schema = 1,
		upatch = input.upatch,
		map = input.map,
		records = dirty_records(input, record_size),
	}
end
