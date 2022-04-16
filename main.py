import discord
from discord.ext import commands
import config as cfg
import vt
import re


prefix = "*"
bot = commands.Bot(command_prefix=prefix)
vtClient = vt.Client(cfg.APIKEY)
channelsWhereScanning =  []
userStatuses = {}
loggingChannel = 0

#Called when the bot logs in
@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')

#Sets the bot up in the channel(to send logs from the channel)
@bot.command()
async def setup(ctx):
    if ctx.channel.id in channelsWhereScanning:
        await ctx.send("I've been already set up in this channel")
    else:
        await ctx.send("Sucessfully set up in <#" + str(ctx.channel.id) + ">")
        channelsWhereScanning.append(ctx.channel.id)
    if loggingChannel == 0:
        await ctx.send("Make sure to setup a logchannel aswell using the 'log' - command")

#Gets the list of the channels the bot has been set up
@bot.command()
async def channels(ctx):
        msg = discord.Embed(title="Channel list",description="All channels i've been set up", color=0xC906E3)
        for x in channelsWhereScanning:
            msg.add_field(name="Channel:",value="<#" + str(x) + ">",inline=False)
        msg.add_field(name="Logchannel:",value="<#" + str(loggingChannel) + ">", inline=False)
        await ctx.send(embed = msg)

#Changes the bots prefix
@bot.command()
async def prefix(ctx, *arg):
    if not arg:
        await ctx.send("You must give a prefix")
    else:
        await ctx.send("Prefix has been set to: " + arg[0])
        bot.command_prefix=arg[0]

#Called when someone sends a message
@bot.event
async def on_message(ctx):
    await bot.process_commands(ctx)
    #Scans the message if there is a URL then scans it with VirusTotal
    await scan(ctx)
    if "<" in ctx.content and ">" in ctx.content:
        await checkforstatus(ctx)

#Sets up the loggingChannel
@bot.command()
async def log(ctx):
    global loggingChannel
    if ctx.channel.id == loggingChannel:
        await ctx.send("Im already set up here")
    else:
        await ctx.send("The logchannel is now:" + "<#" + str(ctx.channel.id) + ">")
        loggingChannel = ctx.channel.id

#Scans the url
async def scan(ctx):
#Checks if the message is a link
    try:
        link = re.search("(?P<url>https?://[^\s]+)", ctx.content).group("url")
        isAUrl = True
    except AttributeError:
        isAUrl = False
#Scans the url
    if(isAUrl and ctx.channel.id in channelsWhereScanning):
        url_id = vt.url_id(link)
        url = await vtClient.get_object_async("/urls/{}", url_id)
        analysis = dict(url.last_analysis_stats)
        l_channel = bot.get_channel(loggingChannel)
        rate = analysis.get('malicious') + analysis.get('suspicious')
        #Sends a log if thr URL is suspicious there is a loggingChannel set up
        if rate > 0 and loggingChannel != 0:
            msg = discord.Embed(title="Scan Results",description="Scanned URL rating", color=0xC906E3)
            msg.add_field(name="URL:",value=link,inline=False)
            msg.add_field(name="Rating:",value="This URL is most likely malicious",inline=False)
            msg.add_field(name="Author:",value=ctx.author,inline=False)
            await l_channel.send(embed = msg)
            await ctx.delete()

#Sets a custom status for the user
@bot.command()
async def status(ctx, *arg):
    if not arg:
        await ctx.send("Make sure to give a status too")
    else:
        currentUserStatus = ""
        for x in arg:
            currentUserStatus += x + " "
        await ctx.send("Set your status to: " + currentUserStatus)
        userStatuses.update({str(ctx.author.id) : currentUserStatus})
    if userStatuses:
        print(userStatuses)

#Deletes the user's status if they got one
@bot.command()
async def delstatus(ctx):
    if str(ctx.author.id) in userStatuses.keys():
        await ctx.send("Deleted your status sucessfully")
        del userStatuses[str(ctx.author.id)]
    else:
        await ctx.send("You dont have a status set")
    if userStatuses:
        print(userStatuses)

async def checkforstatus(ctx):
    mentionedId = str(ctx.content)
    removableChars = "<>@"
    for c in removableChars:
        mentionedId=mentionedId.replace(c,"")
    if mentionedId in userStatuses.keys() and str(ctx.author.id) != mentionedId:
        await ctx.channel.send("This user is currently : " + userStatuses.get(mentionedId))

bot.run(cfg.TOKEN)