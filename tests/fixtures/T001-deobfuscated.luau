--!strict

type Input = { number } | string
type Phase = "marker" | "length" | "payload" | "checksum"

local MARKER = 0xAA
local CHECKSUM_MODULUS = 256

-- Scans framed numeric data and returns valid count, invalid count, and accepted checksums.
local function scanFrames(input: Input): (number, number, string)
	-- Numeric indexing of a plain Luau string yields nil; it does not read a byte.
	local values = input :: { number }
	local acceptedChecksums: { number } = {}
	local validCount, invalidCount = 0, 0
	local phase: Phase = "marker"
	local expectedLength, payloadCount, checksum = 0, 0, 0

	for index = 1, #input do
		local value = values[index]
		if phase == "marker" then
			if value == MARKER then
				checksum = 0
				phase = "length"
			end
		elseif phase == "length" then
			if value > 0 then
				expectedLength = value
				payloadCount = 0
				phase = "payload"
			else
				phase = "checksum"
			end
		elseif phase == "payload" then
			checksum = (checksum + value) % CHECKSUM_MODULUS
			payloadCount += 1
			if payloadCount >= expectedLength then
				phase = "checksum"
			end
		else
			if value == checksum then
				validCount += 1
				acceptedChecksums[#acceptedChecksums + 1] = checksum
			else
				invalidCount += 1
			end
			phase = "marker"
		end
	end

	return validCount, invalidCount, table.concat(acceptedChecksums, ",")
end

return scanFrames
