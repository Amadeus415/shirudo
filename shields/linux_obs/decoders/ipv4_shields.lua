local function metric_point(input, value, outcome)
	return {
		startTimeUnixNano = input.startTimeUnixNano,
		timeUnixNano = input.timeUnixNano,
		asInt = value,
		attributes = {
			{key = "outcome", value = {stringValue = outcome}},
		},
	}
end

function decode(input)
	if not input.data.serialized or input.data.serialized_bytes ~= 32 then
		error("unexpected IPv4 shields counter payload")
	end
	local records = shirudo.fixed_records(input.data.pages, 16)
	-- fixed_records reserves Lua slot 1 for the serialized page header.
	local record = records[2]
	if not record then
		error("missing IPv4 shields counter record")
	end
	return {
		{name = "enforcement.ipv4_shields_metric", unit = "1",
			description = "IPv4 TCP connect and UDP send decisions",
			sum = {
				aggregationTemporality = 2,
				isMonotonic = true,
				dataPoints = {
					metric_point(input, record:u64(0), "allowed"),
					metric_point(input, record:u64(8), "denied"),
				},
			}},
	}
end
