local function dirty_records(input)
	local slots = shirudo.fixed_records(input.data.pages, 48)
	local records = {}
	for _, page in ipairs(input.data.pages) do
		local count = math.floor(page.bytes / 48)
		for i = 1, count - 1 do
			local record = slots[page.cursor + i + 1]
			if record and record:u32(28) ~= 0 then
				records[#records + 1] = record
			end
		end
	end
	return records
end

function decode(input)
	local data_points = {}
	for _, record in ipairs(dirty_records(input)) do
		data_points[#data_points + 1] = {
			startTimeUnixNano = input.startTimeUnixNano,
			timeUnixNano = input.timeUnixNano,
			asInt = record:u64(32),
			attributes = {
				{key = "javaagent.jar_id", value = {stringValue = record:u64(0)}},
				{key = "javaagent.hook_id", value = {stringValue = record:u64(8)}},
				{key = "process.executable.ino", value = {stringValue = record:u64(16)}},
				{key = "process.executable.dev", value = {stringValue = tostring(record:u32(24))}},
			},
		}
	end
	return {
		{
			name = "shirudo.javaagent.sql_injection_attempts",
			unit = "1",
			sum = {
				aggregationTemporality = 2,
				isMonotonic = true,
				dataPoints = data_points,
			},
		},
	}
end
