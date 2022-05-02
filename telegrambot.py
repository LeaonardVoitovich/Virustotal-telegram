import math
import os
import time

from pyrogram import Client, filters
from pyrogram.types import BotCommand

from config import Config
from virustotal import virus

msgdic = {}

app = Client(
    "hey",
    api_id=Config.APP_ID,
    api_hash=Config.API_HASH,
    bot_token=Config.BOT_TOKEN
)


# def progress(client, current, total, message_id, chat_id, start):
#     now = time.time()
#     diff = now - start
#     if round(diff % 5.00) == 0 or current == total:
#         percentage = current * 100 / total
#         speed = current / diff
#         elapsed_time = round(diff) * 1000
#         time_to_completion = round((total - current) / speed) * 1000
#         estimated_total_time = elapsed_time + time_to_completion
#         elapsed_time = TimeFormatter(milliseconds=elapsed_time)
#         estimated_total_time = TimeFormatter(milliseconds=estimated_total_time)
#         progress = "[{0}{1}] \nPercentage: {2}%\n".format(
#             ''.join(["█" for i in range(math.floor(percentage / 5))]),
#             ''.join(["░" for i in range(20 - math.floor(percentage / 5))]),
#             round(percentage, 2)
#         )
#         tmp = progress + "{0} of {1}\nSpeed: {2}/s\nETA: {3}\n".format(
#             humanbytes(current),
#             humanbytes(total),
#             humanbytes(speed),
#             estimated_total_time if estimated_total_time != '' else "0 s"
#         )
#         try:
#             client.edit_message_text(
#                 chat_id,
#                 message_id,
#                 text="Downloading...\n {}".format(tmp)
#             )
#         except:
#             pass
#
#
# def humanbytes(size):
#     if not size:
#         return ""
#     power = 2 ** 10
#     n = 0
#     Dic_powerN = {0: ' ', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
#     while size > power:
#         size /= power
#         n += 1
#     return str(round(size, 2)) + " " + Dic_powerN[n] + 'B'
#
#
# def TimeFormatter(milliseconds: int) -> str:
#     seconds, milliseconds = divmod(int(milliseconds), 1000)
#     minutes, seconds = divmod(seconds, 60)
#     hours, minutes = divmod(minutes, 60)
#     days, hours = divmod(hours, 24)
#     tmp = ((str(days) + "d, ") if days else "") + \
#           ((str(hours) + "h, ") if hours else "") + \
#           ((str(minutes) + "m, ") if minutes else "") + \
#           ((str(seconds) + "s, ") if seconds else "") + \
#           ((str(milliseconds) + "ms, ") if milliseconds else "")
#     return tmp[:-2]

def remove_file(path):
    os.remove(path)


def send_msg(user, txt):
    app.send_message(user, txt)


def check_size(path):
    virus_list = []
    reasons = []
    b = os.path.getsize(path)
    print('file size is', b)
    obj = virus(str(path))

    if b > 32 * 1024 * 1024:
        obj.large_files()
        if not obj.res:
            return 'Error'
    else:
        obj.smallfiles()
        if not obj.res:
            return 'Error'

    time.sleep(7)
    obj.get_report()

    for i in obj.report:
        if obj.report[i]['detected']:
            virus_list.append(i)
            reasons.append('➤ ' + obj.report[i]['result'])

    if len(virus_list) > 0:
        names = ' , '.join(virus_list)
        reason = '\n'.join(reasons)
        msg = '\n☣ --Threats have been detected !-- ☣\n\n**{}** \n\n\n**Description**\n\n`{}`\n\n[Detailed Report]({})'.format(
            names, reason, obj.link)
        return msg
    else:
        msg = '✅VERIFIED✅'
        return msg


@app.on_message(filters.command("start"))
def on_start(client, message):
    commands = app.get_bot_commands()
    if len(commands) == 0:
        app.set_bot_commands([BotCommand("start", "Start the bot")])

    msg = "👋 Hi I'm Web3Forces File-Checker 👋\n\n" \
          "🛠 Send me your file, and I will check it on MALWARES\n" \
          "‼️Requirement FILE SIZE - less than 200MB‼️\n\n" \
          "🌐JOIN OUR COMMUNITY🌐\n" \
          "Chanel - @forcesdao\n" \
          "Chat - @web3daochat\n" \
          "Discord - https://discord.gg/web3forces"

    send_msg(message.chat.id, msg)


@app.on_message(filters.document)
def download_telegram_media(client, message):
    msg = client.send_message(
        chat_id=message.chat.id,
        text='Download is being started...\nPlease Wait !'
    )

    if message.document.file_size > 200 * 1024 * 1024:
        return msg.edit_text("❌File wasn't scanned❌\n⛓< 200MB EXPECTED⛓")

    download_location = client.download_media(message)

    print(download_location)
    check_msg = check_size(str(download_location))
    msg.edit_text(check_msg)

    remove_file(download_location)


@app.on_edited_message
def nothing():
    return


app.run()
