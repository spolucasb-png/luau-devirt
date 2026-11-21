--!strict
local environment = getfenv()
local game = environment.game
local replicatedStorage = game.GetService(game, "ReplicatedStorage")
local events = replicatedStorage.FindFirstChild(replicatedStorage, "Events")
local dialogueEvent = events and events.FindFirstChild(events, "MothDialogueBindable")
local assertDialogue = environment.assert
local validDialogueEvent = dialogueEvent and dialogueEvent.IsA(dialogueEvent, "BindableEvent")
assertDialogue(validDialogueEvent, "MothDialogueBindable not found. Run this inside Nullscape.")

local dialogueOptions: { [any]: any } = {
	Text = "hey its me its celestial",
	EntranceAnimation = "horizontal",
	ExitAnimation = "flash",
	Lifetime = 7.5,
}
dialogueOptions.Position = environment.UDim2.fromScale(0.5, 0.95)
dialogueOptions.InitialSounds = {}
dialogueOptions.NoIdle = false
local markups: { [any]: any } = {}
local colorMarkup: { [any]: any } = { MarkupType = "Color", StartIndex = 1 }
local mathLibrary = environment.math
colorMarkup.EndIndex = mathLibrary.huge
local color3 = environment.Color3
colorMarkup.Value1 = color3.fromRGB(255, 45, 45)
markups[1] = colorMarkup

local shakyMarkup: { [any]: any } = { MarkupType = "Shaky", StartIndex = 1 }
local mathLibrary2 = environment.math
shakyMarkup.EndIndex = mathLibrary2.huge
shakyMarkup.Value1 = 1
shakyMarkup.Value2 = 1
markups[2] = shakyMarkup
dialogueOptions.Markups = markups
dialogueEvent.Fire(dialogueEvent, dialogueOptions)
