import os
import hashlib
import sys
import shutil
import zipfile
from pathlib import Path

# Список відомих шкідливих хешів (SHA-256)
malicious_hashes = {
    "fc748a45a8524436bd615954d2c11e6c942b5c47c16380a81e55458c7702c2f2",
    "d5a6e410ba8ea13b3229888c07a91746538c47b2c26fefd79b500833fa2da1de",
    "5d60d4898d1002bb242908e5037eb4e55e73b1b8a16a2311bf05c336bfa3fc00",
    "0e37b1329d6b6544ef24d204f4146f1445b5cdc33c46447de8e6c2c525f1fd6a",
    "0da8a8a5eadc4fcb63a1ac452d084a8166882b3a9dbe202c574c632a194e50b2",
    "490d00c18b3bbfde087655b955c3ac3a32d36ec5fb8ce2d485ecd34ccce4d1db",
    "bfb8861c57f4bb54628020ff0e95f7d000579f8c3a323bd1d3e6e4a872f3d245",
    "dcee09f8a5fe56552dd43d2400990ab65fde4821b78c87748417f8d5b904889f",
    "2aec68c3818dc471865d8ca5f88d783943c1efff0f66360736a09026565035b4",
    "cada223faa617fb038a5d6040d6bbe318a8d6a455377fbc5362ad82f0b741e2e",
    "4931e5d3811a460f47678631f4bdc82c9c6e9176ae3940403e690bc82e3714a9",
    "0fd55b4277f417ddcf927bc94bff8b96415b9630dfcf3e8aac3e153dc015a4a9",
    "28cf97f72cdba738fe94806e047be6ed4b261c1ef1eceec6f4f30a511d914aa7",
    "10fe9e0b3b861a06727addb3e0291727bdd8cd91bebbed4b3d6bc901aa15dde1",
    "b473ef5a2e4a6af3a8fb6e05a5f337de350ed961465a87525a19074a419071e2",
    "9250596f990b94264d818cde82c3e721fd6e33dfb06a7dd02b3951bef5391b68",
    "d9d31cd0e8d1fbc50a7f4ba656de2d577b00372c871054eec1215c110acbe801",
    "7b387f43bf5aefd8f4bb62ffc70756f0406f0194281a2b991fee89b340ba2170",
    "1b8393fee1e1db145ff63491330bf4ffa243093da889fcf8456a05971b7e7da2",
    "cb920401372c7fa8780d060a37ec4e54a7b966e1c362d2ec41a26bd3c9f4f43f",
    "1cfa7cd31ec2b9516acdce9a0ed1ced63f247f4e76b744e998c8863d05fb6ace",
    "5d78dc803d29fba00eb080a58f1d85c33dbf50834886337083269ca1b5f1c1db",
    "45744105fc251ba770c956308dfb6505d4ca2d8605e89fafa7db544600940048",
    "a9e785de50216ab7987be7403d1bfcf4d7661ebcfdb8c27eb1525c919398ff7d",
    "6fb4945bb73ac3f447fb7af6bd2937395a067a6e0c0900886095436114a17443",
    "3bbe95a65e0ef8862e242d522d85050e25d0897cfe0a19f0739f5499b17eb55b", # wannacry 01(exe)
    "5393ae32ac0338e591278eeb2cfd05a8140e4d98f8654a6da51646c12acbf3c3", # wannacry 02(zip)
    "1fc5e4c8809b39d79324848bceac749000ea572d050c81275ae3053a83ba7d12", # wannacry 03(dll)
    "993d32b3cc9e59664ac57bbe91d5db25a100361bff1f44fea21a33147f98c755", # wannacry 04(exe)
    "ab31092c90dbe2968d95d0ce959365ecdc49ba4384c5f794ebcfb75bab83ab6b", # wannacry 05(zip)
    "495a459881560883953012cec282045c1f388aef5f367c18d1e211adbf3e04ff", # wannacry 05(zip/zip)
    "b1ab81351ec03c050a9424eaac1d1996308a440db04fd95ec5cada60aa524f1a" # petya 01(exe)
    "c0d0665bc0fc83c9204e30057d7c626e80f3ebe1e0554f17930274aa11996ef1", # petya 02(exe)
    "124e57afaa34fee7a6405531b05ceb4466e94f9e1858db976188a36de58156b3", # petya 03(dll)
    "63545fa195488ff51955f09833332b9660d18f8afb16bdf579134661962e548a", # NotPetya 01(exe)
    "afec2b2af3ace2c478382f9366f6cbc9b9579f2c9a4273150fc33a2ccd59284c", # locky 01(exe)
    "f329ea2c754ab196d15c20fbf9abd722fa63630631144c5a409bd2a20172196b", # locky 02(dll)
    "40a340087cc07780bfd61eab92e40f1223a6de88ec191bdedea0b91b16eca2aa", # locky 03(exe)
    "131da83b521f610819141d5c740313ce46578374abb22ef504a7593955a65f07", # Emotet (aka heodo) 01(exe)
    "5cf5fffcedad7b31530dab3beae6a9c5f8e6d0c3791d5495023bf9b329471095", # Emotet (aka heodo) 02(zip)
    "dd9fcdcaf5c26fc27863c86aa65948924f23ab9faa261562cbc9d65ac80d33d4", # Emotet (aka heodo) 03(onenote)
    "7fbe3b41381073a3f687c7b64e01a42f796a25b83f3d194b7fa97974e4ffe916", # Emotet (aka heodo) 04(exe)
    "487f4dd9bdbe94a9cf1a04a8fdec19f16f86864d05d06f0511544b3ff68c850c", # Emotet (aka trickbot) 05(zip)
    "64af94592f6707505fa6f42b58776c3635706a414e6362a92f707df84627679c", # Emotet (aka trickbot) 05(zip/excel)
    "55dd85b37566755ea1ffb022030b413d2722120067abd9b298a89a61f4b790c2", # Emotet (aka trickbot) 05(zip/CDFV2)
    "c111825cd9ce4d7bc82d64eda636d54653d243ec392dc37cee312791e9013d89", # Conficker 01(dll)
    "6aac27448e10b45cdbea6b043c5899f4bb0c7e740fd68cfe7a8dc1d51e3d5f94", # Conficker 02(dll)
    "1fb613ee3b0e7f96f5dea029aae31b86340b0724e88f84a76b386af84d1cf95c", # MyDoom 01(exe)
    "d42fc4dabd9a9e74156d1a856cb542ed2e0796d2d7c6b976c0ac5421a87f9806", # MyDoom 02(exe)
    "79ab393b5c0b62a5e4272793f0f4e4d42762fe4cd7daa4555fb0b2ddb0dc77ee", # Mirai 01(elf)
    "2daec7f55654ee3e962ddf9c0113af8446eb86b1e8edb5dcc4a99d7249af4ffb",
    "78b68d43ec77ce4f25c3ee62bf638ebd4a3a57f474a73b148c2ab4d36fba7a65",
    "bc5718f51a54b7f41685ca162a80b22a0d2502a9ea6cef668c33f9cf1c4ef904",
    "7a2a1b89a482a8ee2204a4c4b30e776d5139e14a055ff00a480ed27a965e23b6", # ValleyRAT 01(exe)
    "7e61fe39d309176b5257b61ee1ebc532ff1757267eadc5bbc866b6f1b0cc6adf", # Wormbook 01(exe)
    "dd5edc5d6ca3505117d9f1b5bccc097dab0cbebfcb7fc373c8131f088b195520" , # Wormbook 02(rar)
    "156ffbc1adf860198501bf76e6428debdfa847e13e73796ee9bad6e982bf94d4", # Agent Tesla 01(exe)
    "3ca8a0832e4692d1af34589dad120895f2565b06f7c4e303ac0db398d76f4db1", # Agent Tesla 02(rar)
    "8fef6cf08bfccf4ecf83865d71a256d6cdfdf08ea69183cf20291449f0c4315b", # Remcos Rat 01(vbs)
    "426b5b0a199596d6854ea4d4de9dfe0aa0d54fdaaf7f549a06f29cee521b5f7e", # Xworm 01(rar)
    "4603f8a5d2537895dc4d1d5e5c7c9d007f079d123f6061f587e3161bcd7ee4e6", # Xworm 02(vbs)
    "71650773a806fe7c9caf81aa196f0102efabf33c3dc6114e7d7075e8e94eee8c",
    "209a201ff990f670277ecac05dfdd47df6e4994eafb5edc951063793dd5e1631",
    "7e176950a5390b3dbcf17559a37722362f28773a84192a47608ffdb28c1360a1",
    "8330c0c79da2a8bdb0177bef86e13af889a040b8a98d2cee33667d92a4789286", # RedLine 01(vbs)
    "198daaa357fea1d108030cc062789b217dc982c71f761a3eaa6ae06545776fc4", 
    "484e2eca5cbdf5730bc88f223118d415bb6fce8e9350f2cd368efe5fb6be2776",
    "c3f63740392bb5974a1c10ef9d0a26394f1ddb548c6121d31a4a845d86cd00bd", # AsyncRAT 01(vbs)
    "cf56e92d46accb0736a0acf28a98b4ac73e182b636019d0baf29cfb4df52a9c7", # CoinMIner
    "a087176565107fc18fcf3a70209bdbdbe3756a8a2e8220d80f60b18330b6670f",
    "51825d0c9dd2e0a5cae6ebc7cfc73998abe9f3eeb1541224d25b633e7e80124c",
    "3c0f06eb8a8b126c8e60e09abc0a147414f1648e29d1f5301735469b41b8ff21",
    "fe67e626cec1bf31f177cc74846bea404f819c24a873a9c17ad4ee921d579492", # XenoRAT 01
    "e3d810d0fb11822c3fababd123c484d7139bbfce98e9b77ade6334dd239f31ca",
    "a64f27423b94c324fe8f2996ddbb1acce86f6846feac34023779fad333f9a455",
    "13f7599c94b9d4b028ce02397717a1282a46f07b9d3e2f8f2b3213fa8884b029", # Lostkeys 01(html)
    "3233668d2e4a80b17e6357177b53539df659e55e06ba49777d0d5171f27565dd", # Lostkeys 02(vbs)
    "6b85d707c23d68f9518e757cc97adb20adc8accb33d0d68faf1d8d56d7840816",
    "77ebb550f38da3f28a65940a4c665ae3a679249ad906aa39387568a1f7ddd3fa",
    "de96af271bf52bdcecaaf555a711f8a1397ed4b8be0d9c16f483253d29deaf62",
    "9733092223c428fc0e44a90b01c7f77a97bb1205def8be1224ac68969182638e",
    "2c9bb93dc2c9f841e58db43ba7dedd490cf7e0fd9e66c4b56a888e25e93a510c",
    "3749a8b0d8d636d871c0fe6712d3e1d01a57e3076a6d41afe3d64b7b2420982a", # Zeus 01
    "b42ba16263875bdd583e42e59a4dc4bf9d26f70cec00ae4bcafc9827e75943e1", # Zeus 02 
    "3ff49706e78067613aa1dcf0174968963b17f15e9a6bc54396a9f233d382d0e6", # Zeus 03
    "269b5b31bacfb2afa825f97e01f76617e71d11cb6391256142dc11eac0e1459d",
    "c980ee1107a12c2da7f71e10b3808e1c60481b1eb9d253ca3b387e5cb246ab50",
    "9fdec91231fe3a709c8d4ec39e25ce8c55282167c561b14917b52701494ac269",
    "5a889e15ac85773d84fc90d2a761eb4d5a2c2391e907366e9d7b683ff3d97164", # viruistest (bat)
    "e25d349dc027bed46375c72260725fa18f255e0f1a25c837e8da9d4ebe480bf5",
    "a66b60536451618fbb7e6e35c7e1a03605ec66020e6392768d391e98aac54737",
    "ddc7c15d520e60dd50393408f7374dd9a6b9ce3ed2376414e7f83e0128d2d45f",
    "a808c442d1b22ff79205704f20c434583a4b10180f848e3fdc7b8d410c4f2d70",
    "87781cda1314f76db832fc746538529658a51fc1dc7186e08ca195cc4d18ab36",
    "90bf9700d267b34aef7963ca51623daab9f4725253735a66e0a56c532f6b32c4",
    "690d584bb489f5de42077147b13d5431ef3cd36e429a90fcdfe02bc97fdbec85",
    "70100dea8750f52f720a739727cd9b6087e20eba4388bfcb6dcd437946512602",
    "6b557be3c75de371fed1ac8719c32208f16130b8d3c560b8e4b2a7447b661e1e",
    "28e883f496dcb23f5674e525d11af181f787c5914b849f232e22712792dfe18b",
    "d005f232dba733233480510687d2e1e7b3857347a8416ae82db9daa1404e6f38",
    "c8dcf4ee90bbfbd52c182aa80974381871fbc2f9b34b4e81dbcc4eed9777212e",
    "2b332adf4e52168cbd2e76866165a5c6f421d15b5778d44f78f0d86c4c26b9fa",
    "a7c7a0a83a788c5497b94eb34ffe4e03edd062f490efbb33b7ed74f9410c30b0",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "089b1081440a30970c863894845ae91e0dcbd8d91d73ac98c731ff3f1606caf6",
    "235a3c262109ad2f7954286cb735040785cf8c728ba35eb3d8d7d935db64aab6",
    "3c5058f664ce2c787ec8e8c6236839a66e5fc433679d719c3e609bdd71daa2ab",
    "147ad250400bb8c5ec2f7542afc82491fd23d665b070db03c17022ec969024a6",
    "44324ab4fcfcac9933670e8969e7ce334ed0d8139df6b6101c003d94480a9305",
    "340351639863a1c01eb0f8e34aafa2a5f36a7ee378c3cb112827ce3e9bfd7a87",
    "8410f85c1710bfefccf0517cbbc91c0019073ced28d66539eeb596a9de8be1a9",
    "f17c9c6b1f1e4434e2688fc0d25d0bca1efb89582c03028f787fa2b9f765c17a",
    "74cb566ec5556fc020f5ceb1db67c2bdc6e9812ec16f98d2138b148c89ebbb99",
    "4dc2054d3023f671df5cd839a1080cba34e8d764897ace57535dcef6b1c11bf5",
    "c3f1d6a7b5a34147a08530f70536828df4bf1875ff7509979b62f90b580f0d33",
    "1589160661b4ca1f6c9177214bd282fd724efadefe940730efa2a6dde9e0a00e",
    "5badd8294b5ab8aebdaef9cef14176ceb4765f170414042e828903e092d93686",
    "82e34351115b01948c0ed5ba16337e6ddd3f519a0b6f681061fd5f50f95fda46",
    "b024d90cd12719f7fe82e8a0b4310f56e6769c2640acefc564e222deabf6a839",
    "07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd",
    "89f4e4f4701c205476928eb8c7251a5165d9720957198ee85ad3f91a32e0fb6c",
    "6e51fa23db7d2f83f3d380d6d465e32621793d8c50e6bde255d996c25288c044",
    "ad55f0db99cb7b4cc2189bb0434d6002f8bd2bf99e25d56d61d12e82dd8320d9",
    "ac73e3c9e7ee62be2d2138fa5f8ef28679c0a191882b7a30e35ce7b89786935f",
    "c94e6405266a5101501962b24eb1c43ad64e271eb3346e8889c610cec267eec2",
    "7ec64083883bc760cd1ae4f84d9b62ca1002833acbe1bbc960f0eddba8bb9ddb",
    "168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db",
    "7fa18253fcff9ea9728834f2768c41f999c7792ca2b11bf4e04696e9cc1ca5b5",
    "ac21ddc972b50c66a9876f1a470f0a29f4df58c1557b8fa0ba649fc0b255dd37",
    "9b8eb1986e07473972937fff3b2dc01064fedcddb2961457659f35f0d28a4b90",
    "4739e4c0865e83189e5d359c1d2aacae1fc0bfc48a55ef5a77111c447e2fc6a3",
    "8d081936bc7f6301a4fe8e7f0641c609c0fe1bd9a5bc2be35fd5eb2dbe5ddc30",
    "e2697ed61b7013476456b4a584697d2b9f38b26c9bd0a5756302202470116e8b",
    "73b4aef863cc032f34c5502f255bfb524708de64456e6e6879480abd0e6b5296",
    "cf84cb0045ed79b96ca0094f52f22fa62ea05142df1466f03a71ab1524c339f9",
    "8091ff36ccffcc45188e48f5a7f7f3e8714291589ba0d6d5ade5776b4c931792",
    "b4b9d129ba597a083715e91c4c65d3a3a2d8fe80fbbc8839e0943a14055b2f6f",
    "5b2d0a6a24bbaf7303616fa6fa358aca29c6ce5ade0cb4f97252c682bab470c0",
    "10720f93bb8ab7020fdd7a4ec0e843d35932269f8eb20cb0245ad8ee7f7e34c7",
}

sus = {
    b"exec",
    b"eval",
    b"execute",
    b"@echo off",
    b"system(",
    b"system32",
    b"-rf",
    b"-fr",
    b"./*",
    b"./",
    b"c3lzdGVtMzI=",
    b"cmd.exe",
    b"terminal.elf",
    b"terminal.exe",
    b"terminal",
    b".bat > ",
    b".bat>",
    b"del ",
    b"73797374656d3332",
    b"ON4XG5DFNUZTE===",
    b"LKFJEjrd6Sd",
    b"521e1a9c811df7dd2223bab70231521007a9bd4c",
    b"4a6a0a4b5679aff5bd985cebd3dd918e8104d2c6bee4fe9c19e4c787f31ec6f9",
    b"bda9f42e0c8a294ecdf5cc72aae6a701",
    b"899c7ac8548f60cf5ae10e9ef8f72bfe",
    b"7141baefe78f91d8a0cdd7e5135589f1",
    b"s y s t e m 3 2",
    b"s-y-s-t-e-m-3-2",
    b"s_y_s_t_e_m_3_2",
    b"s_y_s_t_e_m_3_2_",
    b"_s_y_s_t_e_m_3_2",
    b"_s_y_s_t_e_m_3_2_",
    b"rm -rf ./",
    b"rm -rf ./*",
    b"rm -rf /",
    b"rm -rf .",
    b"rm -fr ./",
    b"rm -fr ./*",
    b"rm -fr /",
    b"rm -fr .",
    b"515c229682fbc207ce68043c51a85fc7",
    b"cm0gLXJmIC4vKg==",
    b"reg ",
    b"keylog",
    b"command_loop",
    b"base64",
    b"hook",
    b"hide_window",
    b"autostart",
    b"connect(",
    b"base64.b64encode(",
    b"base64.b64decode(",
    b"btoa(",
    b"atob("
}

def calculate_file_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb", errors="ignore") as f:
            f.seek(0,2)
            size = f.tell()
            f.seek(0)
            for chunk in iter(lambda: f.read(size), b""):
                sha256.update(chunk)
            return sha256.hexdigest()
    except Exception as e:
        print(f"[Error] {filepath}: {e}")
        return None
    
def fcalculate_file_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb", errors="ignore") as f:
            f.seek(0,2)
            size = f.tell()
            f.seek(0)
            for chunk in iter(lambda: f.read(size), b""):
                sha256.update(chunk)
            return sha256.hexdigest()
    except Exception as e:
        return None

def calculate_file_sus(filepath):
    try:
        with open(filepath, "rb") as f:
            return f.read()
    except Exception as e:
        print(f"[Error] {filepath}: {e}")
        return None

scanned = 0
count = 0
sus_level = 0
sus_c = 0
deleted = 0


def analyze_zip(filepath):
    global scanned, count, sus_level, sus_c, deleted
    try:
        with zipfile.ZipFile(filepath, 'r') as zipf:
            for name in zipf.namelist():
                try:
                    with zipf.open(name) as file:
                        data = file.read()
                        file_hash = hashlib.sha256(data).hexdigest()
                        if file_hash in malicious_hashes:
                            print(f"[DETECTED in ZIP] Bad file detected: {filepath} -> {name}")
                        sus_found = 0
                        for s in sus:
                            if s.lower() in data.lower():
                                sus_found += 1
                        if sus_found > 3:
                            print(f"[SUSPEND in ZIP: {sus_found}] {filepath} -> {name}")
                except Exception as e:
                    print(f"[Error in ZIP] {filepath} -> {name}: {e}")
    except Exception as e:
        print(f"[Error opening ZIP] {filepath}: {e}")
        
def danalyze_zip(filepath):
    global scanned, count, sus_level, sus_c, deleted
    inf = False
    try:
        with zipfile.ZipFile(filepath, 'r') as zipf:
            for name in zipf.namelist():
                try:
                    with zipf.open(name) as file:
                        data = file.read()
                        file_hash = hashlib.sha256(data).hexdigest()
                        if file_hash in malicious_hashes:
                            print(f"[DETECTED in ZIP] Bad file detected: {filepath} -> {name}")
                            inf = True
                            count += 1
                        sus_found = 0
                        for s in sus:
                            if s.lower() in data.lower():
                                sus_found += 1
                        if sus_found > 3:
                            print(f"[SUSPEND in ZIP: {sus_found}] {filepath} -> {name}")
                except Exception as e:
                    print(f"[Error in ZIP] {filepath} -> {name}: {e}")
    except Exception as e:
        print(f"[Error opening ZIP] {filepath}: {e}")
    if inf:
        try:
            os.remove(filepath)
            print(f"[REMOVED] {filepath}")
            deleted += 1
        except Exception as e:
            print(f"[Error removing ZIP] {filepath}: {e}")
            
def qanalyze_zip(filepath):
    quar = Path("quarantine(OpenAV)")
    move = False
    global scanned, count, sus_level, sus_c, deleted
    try:
        with zipfile.ZipFile(filepath, 'r') as zipf:
            for name in zipf.namelist():
                try:
                    with zipf.open(name) as file:
                        data = file.read()
                        file_hash = hashlib.sha256(data).hexdigest()
                        if file_hash in malicious_hashes:
                            print(f"[DETECTED in ZIP] Bad file detected: {filepath} -> {name}")
                            move = True
                        sus_found = 0
                        for s in sus:
                            if s.lower() in data.lower():
                                sus_found += 1
                        if sus_found > 3:
                            print(f"[SUSPEND in ZIP: {sus_found}] {filepath} -> {name}")
                except Exception as e:
                    print(f"[Error in ZIP] {filepath} -> {name}: {e}")
    except Exception as e:
        print(f"[Error opening ZIP] {filepath}: {e}")
    if move:
        quar.mkdir(exist_ok=True)
        npath = quar / (filepath.name + ".openAV_zip")
        shutil.move(str(filepath), str(npath))

def scan_directory(directory, skip=None):
    skip = skip.split(",") if skip is not None else None
    global scanned, count, sus_level, sus_c
    print(f"[Scanning] {directory}")
    for root, _, files in os.walk(directory):
        for name in files:
            filepath = os.path.join(root, name)
            if name.lower().endswith('.zip'):
                analyze_zip(filepath)
                continue
            if skip is not None:
                ext = Path(filepath).suffix.lower()
                if ext in skip:
                    continue    
            file_hash = calculate_file_hash(filepath)
            file_ = calculate_file_sus(filepath)
            if file_hash:
                if file_hash in malicious_hashes:
                    print(f"[DETECTED] Bad file detected: {filepath}")
                    count += 1
                    scanned += 1
                else:
                    scanned += 1
                    print(f"[OK] {filepath}")
            if file_ and file_hash not in malicious_hashes:
                sus_found = 0
                for s in sus:
                    if s.lower() in file_.lower():
                        sus_found += 1
                if name.lower().endswith((".bat")) or name.lower().endswith((".vbs")) or name.lower().endswith((".7z")):
                    sus_found += 1
                if sus_found > 3:
                    sus_level += sus_found
                    sus_c += 1
                    if sus_found < 20:
                        print(f"[SUSPEND: {sus_found}] {filepath}")
                    else:
                        print(f"[WARNING: {sus_found}] {filepath}")
                        count += 1
                    
def fscan_directory(directory, skip=None):
    skip = skip.split(",") if skip is not None else None
    global scanned, count, sus_level, sus_c
    print(f"[Scanning] {directory}")
    for root, _, files in os.walk(directory):
        for name in files:
            filepath = os.path.join(root, name)
            if name.lower().endswith('.zip'):
                analyze_zip(filepath)
                continue
            if skip is not None:
                ext = Path(filepath).suffix.lower()
                if ext in skip:
                    continue  
            file_hash = calculate_file_hash(filepath)
            file_ = calculate_file_sus(filepath)
            if file_hash:
                if file_hash in malicious_hashes:
                    print(f"[DETECTED] Bad file detected: {filepath}")
                    count += 1
                    scanned += 1
                else:
                    scanned += 1
            if file_ and file_hash not in malicious_hashes:
                sus_found = 0
                for s in sus:
                    if s.lower() in file_.lower():
                        sus_found += 1
                if name.lower().endswith((".bat")) or name.lower().endswith((".vbs")) or name.lower().endswith((".7z")):
                    sus_found += 1
                if sus_found > 3:
                    sus_level += sus_found
                    sus_c += 1
                    if sus_found < 20:
                        print(f"[SUSPEND: {sus_found}] {filepath}")
                    else:
                        print(f"[WARNING: {sus_found}] {filepath}")
                        count += 1
                        
def qscan_directory(directory, skip=None):
    skip = skip.split(",") if skip is not None else None
    quar = Path("quarantine(OpenAV)")
    global scanned, count, sus_level, sus_c
    print(f"[Scanning] {directory}")
    for root, _, files in os.walk(directory):
        for name in files:
            filepath = Path(os.path.join(root, name))
            if name.lower().endswith('.zip'):
                qanalyze_zip(filepath)
                continue
            if skip is not None:
                ext = Path(filepath).suffix.lower()
                if ext in skip:
                    continue  
            file_hash = calculate_file_hash(filepath)
            file_ = calculate_file_sus(filepath)
            if file_hash:
                if file_hash in malicious_hashes:
                    print(f"[DETECTED] Bad file detected: {filepath}(moved to quarantine folder)")
                    count += 1
                    scanned += 1
                    quar.mkdir(exist_ok=True)
                    npath = quar / (filepath.name + ".openAV_txt")
                    shutil.move(str(filepath), str(npath))
                else:
                    scanned += 1
            if file_ and file_hash not in malicious_hashes:
                sus_found = 0
                for s in sus:
                    if s.lower() in file_.lower():
                        sus_found += 1
                if name.lower().endswith((".bat", ".vbs", ".7z")):
                    sus_found += 1
                if sus_found > 3:
                    sus_level += sus_found
                    sus_c += 1
                    if sus_found < 20:
                        print(f"[SUSPEND: {sus_found}] {filepath}")
                    else:
                        print(f"[WARNING: {sus_found}] {filepath}(moved to quarantine folder)")
                        quar.mkdir(exist_ok=True)
                        npath = quar / (filepath.name + ".openAV_txt")
                        shutil.move(str(filepath), str(npath))
                        count += 1                    

def dscan_directory(directory, skip=None):
    skip = skip.split(",") if skip is not None else None
    global scanned, count, sus_level, sus_c, deleted
    print(f"[Scanning] {directory}")
    for root, _, files in os.walk(directory):
        for name in files:
            filepath = os.path.join(root, name)
            if name.lower().endswith('.zip'):
                danalyze_zip(filepath)
                continue
            if skip is not None:
                ext = Path(filepath).suffix.lower()
                if ext in skip:
                    continue  
            file_hash = calculate_file_hash(filepath)
            file_ = calculate_file_sus(filepath)
            if file_hash:
                if file_hash in malicious_hashes:
                    print(f"[DETECTED] Bad file detected: {filepath}(removed)")
                    count += 1
                    scanned += 1
                    deleted += 1
                    os.remove(filepath)
                else:
                    scanned += 1
            if file_ and file_hash not in malicious_hashes:
                sus_found = 0
                for s in sus:
                    if s.lower() in file_.lower():
                        sus_found += 1
                if name.lower().endswith((".bat")) or name.lower().endswith((".vbs")) or name.lower().endswith((".7z")):
                    sus_found += 1
                if sus_found > 3:
                    sus_level += sus_found
                    sus_c += 1
                    if sus_found < 20:
                        print(f"[SUSPEND: {sus_found}] {filepath}")
                    else:
                        print(f"[WARNING: {sus_found}] {filepath}")
                        count += 1
                        
def ufscan_directory(directory, skip=None):
    skip = skip.split(",") if skip is not None else None
    global scanned, count, sus_level, sus_c
    print(f"[Scanning] {directory}")
    for root, _, files in os.walk(directory):
        for name in files:
            filepath = os.path.join(root, name)
            if name.lower().endswith('.zip'):
                analyze_zip(filepath)
                continue
            if skip is not None:
                ext = Path(filepath).suffix.lower()
                if ext in skip:
                    continue  
            file_hash = fcalculate_file_hash(filepath)
            file_ = calculate_file_sus(filepath)
            if file_hash:
                if file_hash in malicious_hashes:
                    print(f"[DETECTED] Bad file detected: {filepath}")
                    count += 1
                    scanned += 1
                else:
                    scanned += 1
            if file_ and file_hash not in malicious_hashes:
                sus_found = 0
                for s in sus:
                    if s.lower() in file_.lower():
                        sus_found += 1
                if name.lower().endswith((".bat")) or name.lower().endswith((".vbs")) or name.lower().endswith((".7z")):
                    sus_found += 1
                if sus_found > 3:
                    sus_level += sus_found
                    sus_c += 1


if __name__ == "__main__":
        if len(sys.argv) > 2:
            if sys.argv[2] == '--clean':
                path = input("Type path: ").strip()
                if os.path.isdir(path):
                    try:
                        dscan_directory(path)
                        print(f"Detected: {count}\nSuspended: {sus_c}\nDeleted: {deleted}\nScanned: {scanned}")
                    except KeyboardInterrupt:
                        print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
            if sys.argv[2] == '--quarantine':
                path = input("Type path: ").strip()
                if os.path.isdir(path):
                    try:
                        qscan_directory(path)
                        print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    except KeyboardInterrupt:
                        print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
            if sys.argv[2] == '--skip-basic':
                skip_ = ".txt,.mp3,.mp4,.webp,.rar,.Msi,.iso,.html,.py,.cpp,.svg,.md,.pdf,.openAV_txt,.openAV_zip,.json,.sql,.htm,.hpp,.h,.so,.ink,.lib,.image,.img,.webm"
                if len(sys.argv) < 2:
                    path = input("Type path: ").strip()
                    if os.path.isdir(path):
                        try:
                            scan_directory(path, skip_)
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        except KeyboardInterrupt:
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    else:
                        print("❌ No path.")
                else:
                    if sys.argv[1] == '--clean':
                            path = input("Type path: ").strip()
                            if os.path.isdir(path):
                                try:
                                    dscan_directory(path, skip_)
                                    print(f"Detected: {count}\nSuspended: {sus_c}\nDeleted: {deleted}\nScanned: {scanned}")
                                except KeyboardInterrupt:
                                    print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    if sys.argv[1] == '--quarantine':
                            path = input("Type path: ").strip()
                            if os.path.isdir(path):
                                try:
                                    qscan_directory(path, skip_)
                                    print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                                except KeyboardInterrupt:
                                    print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    if sys.argv[1] == '--fast':
                        path = input("Type path: ").strip()
                        if os.path.isdir(path):
                            try:
                                fscan_directory(path, skip_)
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                            except KeyboardInterrupt:
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        else:
                            print("❌ No path.")
                    if sys.argv[1] == '--ufast':
                        path = input("Type path: ").strip()
                        if os.path.isdir(path):
                            try:
                                ufscan_directory(path, skip_)
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                            except KeyboardInterrupt:
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        else:
                            print("❌ No path.")
                    if sys.argv[1] == '--full':
                        path = "C:\\"
                        if os.path.isdir(path):
                            try:
                                fscan_directory(path, skip_)
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                            except KeyboardInterrupt:
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        path = "D:\\"
                        if os.path.isdir(path):
                            try:
                                fscan_directory(path, skip_)
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                            except KeyboardInterrupt:
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        else:
                            print("❌ No path.")
                    if sys.argv[1] == '--full-fast':
                        path = "C:\\"
                        if os.path.isdir(path):
                            try:
                                ufscan_directory(path, skip_)
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                            except KeyboardInterrupt:
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        path = "D:\\"
                        if os.path.isdir(path):
                            try:
                                ufscan_directory(path, skip_)
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                            except KeyboardInterrupt:
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        else:
                            print("No path.")
        else:
            if len(sys.argv) < 2:
                path = input("Type path: ").strip()
                if os.path.isdir(path):
                    try:
                        scan_directory(path)
                        print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    except KeyboardInterrupt:
                        print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                else:
                    print("❌ No path.")
            else:
                if sys.argv[1] == '--clean':
                        path = input("Type path: ").strip()
                        if os.path.isdir(path):
                            try:
                                dscan_directory(path)
                                print(f"Detected: {count}\nSuspended: {sus_c}\nDeleted: {deleted}\nScanned: {scanned}")
                            except KeyboardInterrupt:
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                if sys.argv[1] == '--quarantine':
                        path = input("Type path: ").strip()
                        if os.path.isdir(path):
                            try:
                                qscan_directory(path)
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                            except KeyboardInterrupt:
                                print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                if sys.argv[1] == '--fast':
                    path = input("Type path: ").strip()
                    if os.path.isdir(path):
                        try:
                            fscan_directory(path)
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        except KeyboardInterrupt:
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    else:
                        print("❌ No path.")
                if sys.argv[1] == '--ufast':
                    path = input("Type path: ").strip()
                    if os.path.isdir(path):
                        try:
                            ufscan_directory(path)
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        except KeyboardInterrupt:
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    else:
                        print("❌ No path.")
                if sys.argv[1] == '--full':
                    path = "C:\\"
                    if os.path.isdir(path):
                        try:
                            fscan_directory(path)
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        except KeyboardInterrupt:
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    path = "D:\\"
                    if os.path.isdir(path):
                        try:
                            fscan_directory(path)
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        except KeyboardInterrupt:
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    else:
                        print("❌ No path.")
                if sys.argv[1] == '--full-fast':
                    path = "C:\\"
                    if os.path.isdir(path):
                        try:
                            ufscan_directory(path)
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        except KeyboardInterrupt:
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    path = "D:\\"
                    if os.path.isdir(path):
                        try:
                            ufscan_directory(path)
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                        except KeyboardInterrupt:
                            print(f"Detected: {count}\nSuspended: {sus_c}\nScanned: {scanned}")
                    else:
                        print("No path.")
