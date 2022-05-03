# Moonlight
Howl and release Wizard101 traffic's true form

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Moonlight is a Wizard101 game traffic decoder designed to take unencrypted packet captures of KI traffic and turn them into something a human can understand.

## Beta Disclaimer
This package is still in a beta phase. Commands, outputs, etc are subject to change without a major version bump. Please excersice caution.

## Commands
Moonlight uses `click` to create a command line interface. Use `moonlight --help` to get more detailed command information. Nearly all commands require a reference to a folder containing the Wizard101 client revision's DML message protocol definitions. See below for more information on that.

- decode
  - packet: Decode a single packet in several different input formats
  - pcap: Decodes a wireshark packet capture file into a JSON file where all KI packets are disassembled
- pcap
  - filter: Removes non-KI packets from a packet capture to make storage easier. Optionally sanitizes sensitive info in KI packets such as login keys.



### Decode pcap
This command is the heart and soul of moonlight. When fed a packet capture containing KI and/or netpack traffic, it converts it into readable information. For example, a packet like this (not showing ports/timestamps and the like)

```
0D F0 12 00 00 00 00 00 05 4C 0D 00 EB 75 50 03 00 00 46 00 09 00
```

is now this

```json
{
  "sender": "SERVER",
  "timestamp": "2022-04-24T12:17:11.158159",
  "raw": "0D F0 12 00 00 00 00 00 05 4C 0D 00 EB 75 50 03 00 00 46 00 09 00",
  "data": {
    "format": "DML",
    "name": "MSG_EQUIPMENTBEHAVIOR_PUBLICUNEQUIPITEM",
    "fields": {
      "GlobalID": {
        "value": 19703248425350635,
        "format": "GID"
      },
      "IndexToRemove": {
        "value": 9,
        "format": "UBYT"
      }
    }
  }
}
```


## KI Proprietary Data
Moonlight depends on KI proprietary information to decode network traffic properly. These are not and never will be included in the package. Instead, they must be gathered by the user.

### Message Protocol Definitions
KI uses a custom data transfer language called DML (data markup language [ironically not a markup language]). This involves XML files defining how messages are structured and the information within them. They change with every feature-adding update.

To get these files, there are several open source programs in the wild that can be used.
- [WizWalker](https://github.com/StarrFox/wizwalker)
- [KIWad (a kronos team project)](https://github.com/kronos-project/kiwad)
- quickbms if you're able to get it

Extract the `root.wad` file within the KI data folder using one of the above tools. All messages can be pulled out of the directory tree with the following commands.

```bash
KI_WAD_FOLDER=?
EXPORT_FOLDER=?

cd $KI_WAD_FOLDER

find . | grep -iE "Messages[0-9]?.xml" | xargs -I % cp % $EXPORT_FOLDER
```

### WizWalker Typedefs
The [WizWalker](https://github.com/StarrFox/wizwalker) tool is capable of poking around the `WizardGraphicalClient.exe` file and grabbing information on the structure of the game's internal objects. These are needed to turn a significant number of DML message fields that are in plain binary back into readable information. Note that moonlight  **does not require** these typedefs and will work normally without them, but the contents of mny DML messages will still be garbled.

### Netpack Flag Tool
Netpack's flag tool data is needed alongside wizwalker typedefs in order to fully decode many DML messages. This is still a WIP effort and Kronos-team internal.

# Ethics and Legal Statements
The information and implementations within moonlight were created via cleanroom reverse engineering and the hard work of other community members especially StarrFox's WizWalker project. No intellectual property of KI is within this repository and never will be. No leaks of internal resources were ever viewed by moonlight's developers.

In the case that there *is* proprietary files within this repo, please let me know ASAP and I will purge them from the entire git history. They should not be here.

In the past, moonlight could have been used to cheat in PvP activities, especially beastmoon. In fact, this project started as an attempt to make a better GUI for beastmoon due to problems like missing "time" messages and extreme delay of toast messages about ongoing capture attempts. Because of the encryption implemented by KI, this is no longer a concern for the live game and makes me more confortable having this package publically available. This package *cannot* decrypt KI game traffic.