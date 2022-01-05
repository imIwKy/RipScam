import discord
from discord.ext import commands
import config as cfg
import vt
import re


prefix = "*"
bot = commands.Bot(command_prefix=prefix)
isSetup = False
vtclient = vt.Client(cfg.APIKEY)
checkchannels =  []
logchannel = 0

@bot.event
async def on_ready():
    #Print in the console if the bot has connected to discord
    print(f'{bot.user} has connected to Discord!')

#Sets the bot up in the channel(to send logs from the channel)
@bot.command()
async def setup(ctx):
    if ctx.channel.id in checkchannels:
        await ctx.send("I've been already set up in this channel")
    else:
        await ctx.send("Sucessfully set up in <#" + str(ctx.channel.id) + ">")
        checkchannels.append(ctx.channel.id)
    if logchannel == 0:
        await ctx.send("Make sure to setup a logchannel aswell using the 'log' - command")

#Gets the list of the channels the bot has been set up
@bot.command()
async def channels(ctx):
        msg = discord.Embed(title="Channel list",description="All channels i've been set up", color=0xC906E3)
        for x in checkchannels:
            msg.add_field(name="Channel:",value="<#" + str(x) + ">",inline=False)
        msg.add_field(name="Logchannel:",value="<#" + str(logchannel) + ">", inline=False)
        await ctx.send(embed = msg)

#Changes the bots prefix
@bot.command()
async def prefix(ctx, *arg):
    if not arg:
        await ctx.send("You must give a prefix")
    else:
        await ctx.send("Applying the new prefix: " + arg[0])
        bot.command_prefix=arg[0]

#Check if the message contains a link scans it and if the logchannel was set up send a log and deletes the message
@bot.event
async def on_message(ctx):
    await bot.process_commands(ctx)
    link = re.search("(?P<url>https?://[^\s]+)", ctx.content).group("url")
    url_id = vt.url_id(link)
    url = await vtclient.get_object_async("/urls/{}", url_id)
    analysis = dict(url.last_analysis_stats)
    l_channel = bot.get_channel(logchannel)
    if analysis.get('malicious') or analysis.get('suspicious') > 0 and isSetup and len(checkchannels) != 0:
        msg = discord.Embed(title="Scan Results",description="Scanned URL rating", color=0xC906E3)
        msg.add_field(name="URL:",value=link,inline=False)
        msg.add_field(name="Rating:",value="This URL is most likely malicious",inline=False)
        msg.add_field(name="Author:",value=ctx.author,inline=False)
        await l_channel.send(embed = msg)
        await ctx.delete() 

#Sets up the logchannel
@bot.command()
async def log(ctx):
    global logchannel
    if ctx.channel.id == logchannel:
        await ctx.send("Im already set up here")
    else:
        await ctx.send("This is my logchannel now:" + "<#" + str(ctx.channel.id) + ">")
        logchannel = ctx.channel.id
        isSetup = True

bot.run(cfg.TOKEN)