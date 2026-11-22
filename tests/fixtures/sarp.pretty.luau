--!strict

-- Statically recovered from the VM; external calls retain their source order.
local environment = getfenv()

local game = environment.game
local replicatedStorage = game.GetService(game, "ReplicatedStorage")
local events = replicatedStorage.FindFirstChild(replicatedStorage, "Events")
local dialogueEvent: any = events and events.FindFirstChild(events, "MothDialogueBindable")
local assertDialogue = environment.assert
local validDialogueEvent: any = dialogueEvent and dialogueEvent.IsA(dialogueEvent, "BindableEvent")

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
colorMarkup.EndIndex = environment.math.huge
colorMarkup.Value1 = environment.Color3.fromRGB(255, 45, 45)
markups[1] = colorMarkup

local shakyMarkup: { [any]: any } = { MarkupType = "Shaky", StartIndex = 1 }
shakyMarkup.EndIndex = environment.math.huge
shakyMarkup.Value1 = 1
shakyMarkup.Value2 = 1
markups[2] = shakyMarkup
dialogueOptions.Markups = markups

dialogueEvent.Fire(dialogueEvent, dialogueOptions)
