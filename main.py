import discord
from discord.ext import commands
import config as cfg
import vt
import re


prefix = "*"
bot = commands.Bot(command_prefix=prefix)
isFromScanChannel = False
vtClient = vt.Client(cfg.APIKEY)
scanChannels =  []
userStats = {}
logChannel = 0

#Called when the bot logs in
@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')

#Sets the bot up in the channel(to send logs from the channel)
@bot.command()
async def setup(ctx):
    if ctx.channel.id in scanChannels:
        await ctx.send("I've been already set up in this channel")
    else:
        await ctx.send("Sucessfully set up in <#" + str(ctx.channel.id) + ">")
        scanChannels.append(ctx.channel.id)
    if logChannel == 0:
        await ctx.send("Make sure to setup a logchannel aswell using the 'log' - command")

#Gets the list of the channels the bot has been set up
@bot.command()
async def channels(ctx):
        msg = discord.Embed(title="Channel list",description="All channels i've been set up", color=0xC906E3)
        for x in scanChannels:
            msg.add_field(name="Channel:",value="<#" + str(x) + ">",inline=False)
        msg.add_field(name="Logchannel:",value="<#" + str(logChannel) + ">", inline=False)
        await ctx.send(embed = msg)

#Changes the bots prefix
@bot.command()
async def prefix(ctx, *arg):
    if not arg:
        await ctx.send("You must give a prefix")
    else:
        await ctx.send("Applying the new prefix: " + arg[0])
        bot.command_prefix=arg[0]

#Called when someone sends a message
@bot.event
async def on_message(ctx):
    await bot.process_commands(ctx)
    #Scans the message if there is a URL then scans it with VirusTotal
    await scan(ctx)

#Sets up the logChannel
@bot.command()
async def log(ctx):
    global logChannel
    if ctx.channel.id == logChannel:
        await ctx.send("Im already set up here")
    else:
        await ctx.send("This is my logChannel now:" + "<#" + str(ctx.channel.id) + ">")
        logChannel = ctx.channel.id

#Scans the url
async def scan(ctx):
    #Checks if the message contains a URL
    try:
        link = re.search("(?P<url>https?://[^\s]+)", ctx.content).group("url")
        url_id = vt.url_id(link)
        url = await vtClient.get_object_async("/urls/{}", url_id)
        analysis = dict(url.last_analysis_stats)
        l_channel = bot.get_channel(logChannel)
        rate = analysis.get('malicious') + analysis.get('suspicious')
        #Checks if the message was sent from a channel where the bot is set up
        for x in scanChannels:
            if x == ctx.channel.id:
                isFromScanChannel = True
                #Sends a log if thr URL is suspicious there is a logChannel set up
                #And the message was sent from a channel where the bot is set up
                if rate > 0 and logChannel != 0 and isFromScanChannel:
                    msg = discord.Embed(title="Scan Results",description="Scanned URL rating", color=0xC906E3)
                    msg.add_field(name="URL:",value=link,inline=False)
                    msg.add_field(name="Rating:",value="This URL is most likely malicious",inline=False)
                    msg.add_field(name="Author:",value=ctx.author,inline=False)
                    await l_channel.send(embed = msg)
                    await ctx.delete()
            else:
                print("[URLSCAN]Nothing to see cuz no setup there")
    except AttributeError:
        print("[URLSCAN]Not a Link")

@bot.command()
async def status(ctx, *arg):
    if not arg:
        await ctx.send("Make sure to give a status too")
    else:
        cUStat = ""
        for x in arg:
            cUStat += x + " "
        await ctx.send("Setting your status to: " + cUStat)
        userStats.update({str(ctx.author.id) : cUStat})
    print(userStats)

@bot.command()
async def delstatus(ctx):
    for x in userStats.keys():
        if str(ctx.author.id) == x:
            await ctx.send("Deleting your status")
            del userStats[str(ctx.author.id)]
        else:
            await ctx.send("You dont have a status set")
    print(userStats)


bot.run(cfg.TOKEN)