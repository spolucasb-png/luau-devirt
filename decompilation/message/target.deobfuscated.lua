--!strict

-- Statically recovered from the VM; external calls retain their source order.
local environment = getfenv()

local game = environment.game
local getService = game.GetService
local replicatedStorage = getService(game, "ReplicatedStorage")
local findFirstChild = replicatedStorage.FindFirstChild
local events = findFirstChild(replicatedStorage, "Events")
local dialogueEvent: any = events
if events then
	local findFirstChild2 = events.FindFirstChild
	local foundDialogueEvent = findFirstChild2(events, "MothDialogueBindable")
	dialogueEvent = foundDialogueEvent
end
local assertDialogue = environment.assert
local validDialogueEvent: any = dialogueEvent
if dialogueEvent then
	local isA = dialogueEvent.IsA
	local isBindableEvent = isA(dialogueEvent, "BindableEvent")
	validDialogueEvent = isBindableEvent
end
assertDialogue(validDialogueEvent, "MothDialogueBindable not found. Run this inside Nullscape.")
local dialogueOptions: { [any]: any } = {}
dialogueOptions.Text = "hey its me its celestial"
dialogueOptions.EntranceAnimation = "horizontal"
dialogueOptions.ExitAnimation = "flash"
dialogueOptions.Lifetime = 7.5
local uDim2 = environment.UDim2
local fromScale = uDim2.fromScale
local dialoguePosition = fromScale(0.5, 0.95)
dialogueOptions.Position = dialoguePosition
local initialSounds: { [any]: any } = {}
dialogueOptions.InitialSounds = initialSounds
dialogueOptions.NoIdle = false
local markups: { [any]: any } = {}
local colorMarkup: { [any]: any } = {}
colorMarkup.MarkupType = "Color"
colorMarkup.StartIndex = 1
local mathLibrary = environment.math
local endIndex = mathLibrary.huge
colorMarkup.EndIndex = endIndex
local color3 = environment.Color3
local fromRGB = color3.fromRGB
local markupColor = fromRGB(255, 45, 45)
colorMarkup.Value1 = markupColor
markups[1] = colorMarkup
local shakyMarkup: { [any]: any } = {}
shakyMarkup.MarkupType = "Shaky"
shakyMarkup.StartIndex = 1
local mathLibrary2 = environment.math
local endIndex2 = mathLibrary2.huge
shakyMarkup.EndIndex = endIndex2
shakyMarkup.Value1 = 1
shakyMarkup.Value2 = 1
markups[2] = shakyMarkup
dialogueOptions.Markups = markups
local fireDialogue = dialogueEvent.Fire
fireDialogue(dialogueEvent, dialogueOptions)
