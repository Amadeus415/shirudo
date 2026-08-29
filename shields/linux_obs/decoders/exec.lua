local function dirty_records(input, slot_size)
	local slots = shirudo.fixed_records(input.data.pages, slot_size)
	local records = {}
	for _, page in ipairs(input.data.pages) do
		local count = math.floor(page.bytes / slot_size)
		for i = 1, count - 1 do
			local record = slots[page.cursor + i + 1]
			if record and record:u8(6) ~= 0 then
				local flags = record:u8(6)
				local item = {
					entry_index = record:u32(0),
					executable = { dev = record:u32(12), ino = record:u64(24) },
					name = record:cstring(56, 32),
					exec_count = record:u64(40),
					last_exec_ns = record:u64(48),
				}
				if math.floor(flags / 2) % 2 == 1 then
					item.parent = { dev = record:u32(16), ino = record:u64(32) }
				else
					item.parent = nil
				end
				records[#records + 1] = item
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
		records = dirty_records(input, 128),
	}
end
