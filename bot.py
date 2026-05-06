import os, re, json, logging, asyncio
from datetime import datetime, timedelta
import discord
from discord.ext import commands

def _env_int(name: str, default: int = 0) -> int:
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default

TOKEN = os.getenv('BOT_TOKEN', '').strip()
PREFIX = '='
LOG_CHANNEL_ID = _env_int('LOG_CHANNEL_ID', 0)
TICKET_CHANNEL_ID = _env_int('TICKET_CHANNEL_ID', 0)
TICKET_STAFF_ROLE_ID = _env_int('TICKET_STAFF_ROLE_ID', 0)
LOCKDOWN_ROLE_ID = _env_int('LOCKDOWN_ROLE_ID', TICKET_STAFF_ROLE_ID)
QUARANTINE_ROLE_ID = _env_int('QUARANTINE_ROLE_ID', 0)
MALICIOUS_LINK_LOG_FILE = 'malicious_links.log'
CUSTOM_LINK_PATTERNS_FILE = 'custom_link_patterns.json'
LOCKDOWN_STATE_FILE = 'lockdown_state.json'
BOT_SETTINGS_FILE = 'bot_settings.json'
CUSTOM_PHISH_RE = None
AUTO_TIMEOUT_NEW_ACCOUNT_DAYS = _env_int('AUTO_TIMEOUT_NEW_ACCOUNT_DAYS', 3)
AUTO_TIMEOUT_DURATION_DAYS = _env_int('AUTO_TIMEOUT_DURATION_DAYS', 28)

# Command role access (up to 8 role IDs per command).
# Add role IDs to allow those roles to use the command through the bot.
# Example: 'ban': [111111111111111111, 222222222222222222]
COMMAND_ROLE_ACCESS = {
    'ban': [],
    'unban': [],
    'kick': [],
    'timeout': [],
    'delete': [],
    'reply': [],
    'cases': [],
    'verify': []
    'lastphish': [],
    'ticketpanel': [],
    'lockall': [],
    'editlockmsg': [],
    'setlockdownrole': [],
    'setquarantinerole': [],
    'setticketstaffrole': [],
    'setautotimeout':[]
    'setlogchannel': [],
    'setmoderatorrole': [],
    'unlock': [],
    'unlockall': [],
}
MAX_ROLES_PER_COMMAND = 8

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('AntiPhish')

# simple phishing detector
URL_RE = re.compile(r'https?://\S+', re.IGNORECASE)
TEXT_URL_RE = re.compile(r'\b(?:https?://|hxxps?://)?(?:www\.)?(?:(?:[a-z0-9-]{1,63})\.)+[a-z]{2,63}(?:/[\w\-./?%&=+#:@~;,]*)?', re.IGNORECASE)
TOKEN_RE = re.compile(r'\b[MNO]?[A-Za-z0-9_-]{22,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,}\b')
PHISH_PATTERNS = [
    r'(?:discord\.gg|discord(?:app)?\.com).*?(?:verify|confirm|nitro|login)',
    r'steam(?:powered)?\.com.*login',
    r'https?://(?:www\.)?grabify\.link(?:/|\?|$)\S*',
    r'\b(?:free|claim|verify|login|secure)\b',
    r'\b(?:bit\.ly|tinyurl|cutt\.ly|short\.link)\b',
    r'/(?:join|gate|redirect)\.php\?(?:id|ref|token)=',
    r'https?://(?:\d{1,3}\.){3}\d{1,3}',
    r'\.(?:xyz|tk|ml|click|top|gq|cf|ga)\b',
]
PHISH_RE = re.compile('|'.join(PHISH_PATTERNS), re.IGNORECASE)
WHITELIST = ('discord.com','discordapp.com','steampowered.com','github.com','youtube.com','x.com','twitter.com')
BLOCKLIST = (
    'steamcoemmunity.com',
    'steancommunity.com',
    'steamcommnunity.com',
    'steamcommunlty.com',
    'steamcornmunity.com',
    'steamcomrnunity.com',
    'steamcormmunity.com',
    'steamcommunty.com',
    'steamcommunitty.com',
    'steamcommunitys.com',
    'steamcornnunity.com',
    'stearncommunity.com',
)
KNOWN_PHISHING_DOMAINS = (
    'discord-app.com',
    'discordnitro.com',
    'dlscord.gift',
    'steamcornmunity.com',
    'steamcomrnunity.com',
    'stearncommunity.com',
    'faceboook-login.com',
    'paypa1.com',
    'micr0soft-login.com',
    'googledrive-sharing.com',
    'dropbox-shared-files.com',
) + BLOCKLIST
whitelist = WHITELIST
blocklist = BLOCKLIST
SUSPICIOUS_HOST_TERMS = re.compile(r'(?:phish|malware|virus|danger|suspicious|fake|secure|bank|alert|portal|redirect)', re.IGNORECASE)
SUSPICIOUS_PATH_TERMS = re.compile(r'/(?:login|verify|secure|warning|scan|payload|download|redirect|auth|account|bank|wallet)', re.IGNORECASE)
SUSPICIOUS_FILE_EXT = re.compile(r'\.(?:exe|scr|bat|cmd|ps1|zip|rar|js)(?:$|\?)', re.IGNORECASE)
RISKY_TLDS = {
    'bond', 'zip', 'mov', 'click', 'top', 'gq', 'cf', 'ga', 'tk', 'ml', 'work',
    'quest', 'country', 'xyz', 'rest', 'cam', 'cfd', 'monster'
}

def _normalize_extracted_text(text: str) -> str:
    if not text:
        return ''
    normalized = text.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
    # OCR often inserts spaces/newlines around separators in URLs.
    normalized = re.sub(r'\s*([.:/])\s*', r'\1', normalized)
    normalized = re.sub(r'\b(h\s*t\s*t\s*p\s*s?)\s*:\s*/\s*/', lambda m: m.group(1).replace(' ', '') + '://', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+', ' ', normalized)
    normalized = re.sub(r'hxxps?://', lambda m: 'https://' if m.group(0).lower().startswith('hxxps') else 'http://', normalized, flags=re.IGNORECASE)
    return normalized


def _normalize_url_candidate(candidate: str) -> str:
    value = _normalize_extracted_text(candidate.strip().strip('`<>[](){}\'\"'))
    if not value:
        return ''
    if not re.match(r'^https?://', value, re.IGNORECASE):
        value = f'http://{value}'
    return value


def _extract_urls_for_analysis(text: str):
    normalized = _normalize_extracted_text(text or '')
    urls = set()
    for match in TEXT_URL_RE.findall(normalized):
        candidate = _normalize_url_candidate(match)
        if candidate:
            urls.add(candidate)
    for match in URL_RE.findall(normalized):
        candidate = _normalize_url_candidate(match)
        if candidate:
            urls.add(candidate)
    return sorted(urls)

def _build_phish_pattern_from_link(raw_link: str):
    normalized_link = _normalize_url_candidate(raw_link or '')
    if not normalized_link:
        return '', ''

    try:
        from urllib.parse import urlparse
        parsed = urlparse(normalized_link)
    except Exception:
        return '', ''

    host = (parsed.hostname or '').lower().strip('.')
    if not host:
        return '', ''

    # Match either a full URL or plain-domain mention of the submitted link.
    path = (parsed.path or '').strip('/')
    host_pattern = re.escape(host)
    if path:
        path_pattern = re.escape(path)
        pattern = rf'(?:https?://|hxxps?://)?(?:www\.)?{host_pattern}/{path_pattern}(?:[/?#]\S*)?'
    else:
        pattern = rf'(?:https?://|hxxps?://)?(?:www\.)?{host_pattern}(?:[/?#]\S*)?'

    return normalized_link, pattern

def is_phish(url: str) -> bool:
    normalized_url = _normalize_extracted_text(url or '')
    if CUSTOM_PHISH_RE is not None and CUSTOM_PHISH_RE.search(normalized_url):
        return True
      
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
    except Exception:
        host = url.lower()
        path = url.lower()
        query = ''

    full = f'{host}{path}?{query}'.lower()
    host = host.lower()
    if any(host == w or host.endswith('.' + w) for w in WHITELIST):
        return False
    if any(host == b or host.endswith('.' + b) for b in blocklist):
        return True
      
    score = 0

    labels = [part for part in host.split('.') if part]
    second_level = labels[-2] if len(labels) >= 2 else ''
    tld = labels[-1] if labels else ''

    # Catch throwaway/random-looking domains often used in short-lived phishing campaigns.
    if tld in RISKY_TLDS:
        score += 1
    if second_level and len(second_level) >= 8 and re.search(r'\d', second_level) and re.search(r'[a-z]', second_level):
        score += 1
    if second_level and re.search(r'[aeiou]', second_level) is None and len(second_level) >= 7:
        score += 1
      
    if PHISH_RE.search(url):
        score += 2
    if SUSPICIOUS_HOST_TERMS.search(host):
        score += 2
    if SUSPICIOUS_PATH_TERMS.search(path):
        score += 1
    if SUSPICIOUS_FILE_EXT.search(full):
        score += 2
    if query and re.search(r'(?:token|id|ref|redirect|url|target)=', query, re.IGNORECASE):
        score += 1

    return score >= 2


def detect_discord_token(text: str):
    return TOKEN_RE.search(text)

class TicketOpenView(discord.ui.View):
    def __init__(self, bot):
        super().__init__(timeout=None)
        self.bot = bot

    @discord.ui.button(label='Open Ticket', style=discord.ButtonStyle.success, custom_id='ticket_open_button')
    async def open_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return await interaction.response.send_message('⚠️ This button can only be used in a server.', ephemeral=True)

        if TICKET_STAFF_ROLE_ID <= 0:
            return await interaction.response.send_message('⚠️ Staff role is not configured.', ephemeral=True)

        has_staff_role = any(role.id == TICKET_STAFF_ROLE_ID for role in interaction.user.roles)
        if not has_staff_role and not interaction.user.guild_permissions.administrator:
            return await interaction.response.send_message('⛔ Only ticket staff can open this ticket.', ephemeral=True)

        topic = interaction.channel.topic if isinstance(interaction.channel, discord.TextChannel) else ''
        owner_id = None
        if topic and 'ticket_owner:' in topic:
            try:
                owner_id = int(topic.split('ticket_owner:', 1)[1].split()[0].strip())
            except Exception:
                owner_id = None

        if not owner_id:
            return await interaction.response.send_message('⚠️ Ticket owner could not be identified from this channel.', ephemeral=True)

        member = interaction.guild.get_member(owner_id)
        if member is None:
            return await interaction.response.send_message('⚠️ Ticket owner is no longer in this server.', ephemeral=True)

        try:
            await interaction.channel.set_permissions(member, send_messages=True, reason=f'Ticket opened by {interaction.user}')
        except Exception:
            log.exception('Failed to open ticket channel')
            return await interaction.response.send_message('⚠️ Failed to open the ticket channel.', ephemeral=True)

        opened_embed = discord.Embed(
            title='✅ Ticket Opened',
            description=f'{member.mention}, your ticket is now open. You can send messages in this channel.',
            color=discord.Color.green(),
            timestamp=datetime.utcnow()
        )
        opened_embed.set_footer(text=f'Opened by {interaction.user}')
        await interaction.response.send_message(embed=opened_embed)

    @discord.ui.button(label='Close Ticket', style=discord.ButtonStyle.danger, custom_id='ticket_close_button')
    async def close_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return await interaction.response.send_message('⚠️ This button can only be used in a server.', ephemeral=True)

        if TICKET_STAFF_ROLE_ID <= 0:
            return await interaction.response.send_message('⚠️ Staff role is not configured.', ephemeral=True)

        has_staff_role = any(role.id == TICKET_STAFF_ROLE_ID for role in interaction.user.roles)
        if not has_staff_role and not interaction.user.guild_permissions.administrator:
            return await interaction.response.send_message('⛔ Only ticket staff can close this ticket.', ephemeral=True)

        if not isinstance(interaction.channel, discord.TextChannel):
            return await interaction.response.send_message('⚠️ This is not a text channel ticket.', ephemeral=True)

        topic = interaction.channel.topic or ''
        owner_id = None
        if topic and 'ticket_owner:' in topic:
            try:
                owner_id = int(topic.split('ticket_owner:', 1)[1].split()[0].strip())
            except Exception:
                owner_id = None

        if owner_id:
            owner = interaction.guild.get_member(owner_id)
            owner_text = str(owner) if owner else str(owner_id)
            self.bot._add_case('ticket_closed', owner_text, interaction.user, f'Closed ticket channel {interaction.channel.name}', {'channel_id': interaction.channel.id})

        await interaction.response.send_message('🗂️ Closing this ticket in 3 seconds...', ephemeral=True)
        await asyncio.sleep(3)
        try:
            await interaction.channel.delete(reason=f'Ticket closed by {interaction.user}')
        except Exception:
            log.exception('Failed to delete ticket channel')


class TicketCreateModal(discord.ui.Modal, title='Create Support Ticket'):
    ticket_title = discord.ui.TextInput(
        label='Ticket Title',
        placeholder='Short summary of your issue',
        min_length=3,
        max_length=100,
        required=True,
    )
    ticket_description = discord.ui.TextInput(
        label='Ticket Description',
        placeholder='Explain your issue in detail',
        style=discord.TextStyle.paragraph,
        min_length=10,
        max_length=1000,
        required=True,
    )

    def __init__(self, bot):
        super().__init__()
        self.bot = bot

    async def on_submit(self, interaction: discord.Interaction):
        await self.bot._create_locked_ticket_from_modal(
            interaction,
            str(self.ticket_title).strip(),
            str(self.ticket_description).strip(),
        )

class TicketPanelView(discord.ui.View):
    def __init__(self, bot):
        super().__init__(timeout=None)
        self.bot = bot

    @discord.ui.button(label='Create Ticket', style=discord.ButtonStyle.primary, custom_id='ticket_create_button')
    async def create_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return await interaction.response.send_message('⚠️ Tickets can only be created inside a server.', ephemeral=True)

        for channel in interaction.guild.text_channels:
            if channel.topic and f'ticket_owner:{interaction.user.id}' in channel.topic:
                return await interaction.response.send_message(
                    f'ℹ️ You already have an open ticket: {channel.mention}',
                    ephemeral=True
                )

        await interaction.response.send_modal(TicketCreateModal(self.bot))

class Bot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix=PREFIX, intents=discord.Intents.all(), help_command=None)
        self.case_records = []
        self.custom_link_patterns = []
        self.settings = {
            'guilds': {},
            'defaults': {
                'log_channel_id': LOG_CHANNEL_ID,
                'moderator_role_id': 0,
                'lockdown_role_id': LOCKDOWN_ROLE_ID,
                'ticket_staff_role_id': TICKET_STAFF_ROLE_ID,
                'quarantine_role_id': QUARANTINE_ROLE_ID,
                'auto_timeout_duration_days': AUTO_TIMEOUT_DURATION_DAYS,
                'auto_timeout_duration_days': AUTO_TIMEOUT_DURATION_DAYS,
            },
        }
        self.lockdown_state = {}
        self.ticket_panel_view = None
        self.ticket_open_view = None
        self._load_cases()
        self._load_custom_link_patterns()
        self._load_settings()
        self._load_lockdown_state()
        self._refresh_custom_phish_regex()
        self._register_commands()
        

    async def setup_hook(self):
        # Views must be created after the event loop is running.
        self.ticket_panel_view = TicketPanelView(self)
        self.ticket_open_view = TicketOpenView(self)
        self.add_view(self.ticket_panel_view)
        self.add_view(self.ticket_open_view)

    def _register_commands(self):
        async def check_callback(ctx, *, text: str):
            await self.check(ctx, text=text)

        async def help_callback(ctx):
            await self.cmd_help(ctx)

        async def ping_callback(ctx):
            await self.ping(ctx)

        async def setlogchannel_callback(ctx, channel: discord.TextChannel = None):
            await self.setlogchannel(ctx, channel=channel)

        async def ban_callback(ctx, member: discord.Member, *, reason='No reason'):
            await self.ban(ctx, member, reason=reason)

        async def unban_callback(ctx, user_id: int, *, reason='No reason'):
            await self.unban(ctx, user_id, reason=reason)

        async def verify_callback(ctx, member: discord.Member, *, reason='Verified by staff'):
            await self.verify(ctx, member, reason=reason)

        async def setautotimeout_callback(ctx, days: int = None):
            await self.setautotimeout(ctx, days=days)

        async def announce_callback(ctx, channel: discord.TextChannel = None, *, text: str):
            await self.announce(ctx, channel=channel, text=text)

        async def kick_callback(ctx, member: discord.Member, *, reason='No reason'):
            await self.kick(ctx, member, reason=reason)

        async def setlockdownrole_callback(ctx, role: discord.Role = None):
            await self.setlockdownrole(ctx, role=role)

        async def setquarantinerole_callback(ctx, role: discord.Role = None):
            await self.setquarantinerole(ctx, role=role)

        async def setticketstaffrole_callback(ctx, role: discord.Role = None):
            await self.setticketstaffrole(ctx, role=role)

        async def timeout_callback(ctx, member: discord.Member, duration: str, *, reason='No reason'):
            await self.timeout(ctx, member, duration, reason=reason)

        async def delete_callback(ctx, amount: int = 5):
            await self.delete(ctx, amount)

        async def cases_callback(ctx, member: discord.Member = None):
            await self.cases(ctx, member)
          
        async def reply_callback(ctx, user_id: int, *, text: str):
            await self.reply(ctx, user_id, text=text)

        async def lastphish_callback(ctx):
            await self.lastphish(ctx)
          
        async def add_link_callback(ctx, *, link: str):
            await self.add_link(ctx, link=link)

        async def setmoderatorrole_callback(ctx, role: discord.Role = None):
            await self.setmoderatorrole(ctx, role=role)

        async def ticketpanel_callback(ctx):
            await self.ticketpanel(ctx)

        async def lockall_callback(ctx, *, message: str = None):
            await self.lockall(ctx, message=message)

        async def editlockmsg_callback(ctx, *, message: str):
            await self.editlockmsg(ctx, message=message)

        async def unlock_callback(ctx, channel_id: int = None):
            await self.unlock(ctx, channel_id=channel_id)

        async def unlockall_callback(ctx):
            await self.unlockall(ctx)
          
        check_cmd = commands.Command(check_callback, name='check')

        help_cmd = commands.Command(help_callback, name='help')
        ping_cmd = commands.Command(ping_callback, name='ping')

        ban_cmd = commands.Command(ban_callback, name='ban')
        ban_cmd.add_check(self._make_command_access_check('ban'))

        unban_cmd = commands.Command(unban_callback, name='unban')
        unban_cmd.add_check(self._make_command_access_check('unban'))

        kick_cmd = commands.Command(kick_callback, name='kick')
        kick_cmd.add_check(self._make_command_access_check('kick'))

        timeout_cmd = commands.Command(timeout_callback, name='timeout')
        timeout_cmd.add_check(self._make_command_access_check('timeout'))

        delete_cmd = commands.Command(delete_callback, name='delete', aliases=['clear'])
        delete_cmd.add_check(self._make_command_access_check('delete'))
        
        verify_cmd = commands.Command(verify_callback, name='verify')
        verify_cmd.add_check(self._make_command_access_check('verify'))

        setautotimeout_cmd = commands.Command(setautotimeout_callback, name='setautotimeout')
        setautotimeout_cmd.add_check(self._make_command_access_check('setautotimeout'))

        announce_cmd = commands.Command(announce_callback, name='announce')
        announce_cmd.add_check(commands.is_owner().predicate)

        cases_cmd = commands.Command(cases_callback, name='cases')
        cases_cmd.add_check(self._make_command_access_check('cases'))

        setlogchannel_cmd = commands.Command(setlogchannel_callback, name='setlogchannel', aliases=['logchannel'])
        setlogchannel_cmd.add_check(self._make_command_access_check('setlogchannel'))

        reply_cmd = commands.Command(reply_callback, name='reply')
        reply_cmd.add_check(self._make_command_access_check('reply'))

        add_link_cmd = commands.Command(add_link_callback, name='add_link', aliases=['addlink'])
        ticketpanel_cmd = commands.Command(ticketpanel_callback, name='ticketpanel')
        ticketpanel_cmd.add_check(self._make_command_access_check('ticketpanel'))

        lastphish_cmd = commands.Command(lastphish_callback, name='lastphish')
        lastphish_cmd.add_check(self._make_command_access_check('lastphish'))

        setmoderatorrole_cmd = commands.Command(setmoderatorrole_callback, name='setmoderatorrole', aliases=['modrole'])
        setmoderatorrole_cmd.add_check(self._make_command_access_check('setmoderatorrole'))

        setlockdownrole_cmd = commands.Command(setlockdownrole_callback, name='setlockdownrole', aliases=['lockrole'])
        setlockdownrole_cmd.add_check(self._make_command_access_check('setlockdownrole'))

        setquarantinerole_cmd = commands.Command(setquarantinerole_callback, name='setquarantinerole', aliases=['quarantinerole'])
        setquarantinerole_cmd.add_check(self._make_command_access_check('setquarantinerole'))

        setticketstaffrole_cmd = commands.Command(setticketstaffrole_callback, name='setticketstaffrole', aliases=['ticketstaff'])
        setticketstaffrole_cmd.add_check(self._make_command_access_check('setticketstaffrole'))

        lockall_cmd = commands.Command(lockall_callback, name='lockall')
        lockall_cmd.add_check(self._make_command_access_check('lockall'))

        editlockmsg_cmd = commands.Command(editlockmsg_callback, name='editlockmsg', aliases=['lockmsg'])
        editlockmsg_cmd.add_check(self._make_command_access_check('editlockmsg'))

        unlock_cmd = commands.Command(unlock_callback, name='unlock')
        unlock_cmd.add_check(self._make_command_access_check('unlock'))

        unlockall_cmd = commands.Command(unlockall_callback, name='unlockall')
        unlockall_cmd.add_check(self._make_command_access_check('unlockall'))

        for command in [
            check_cmd, help_cmd, ping_cmd, ban_cmd, unban_cmd, kick_cmd, timeout_cmd,
            verify_cmd, setautotimeout_cmd, delete_cmd, cases_cmd, reply_cmd, lastphish_cmd,
            add_link_cmd, ticketpanel_cmd, setlogchannel_cmd, setmoderatorrole_cmd,
            setlockdownrole_cmd, setquarantinerole_cmd, setticketstaffrole_cmd,
            lockall_cmd, editlockmsg_cmd, unlock_cmd, unlockall_cmd, announce_cmd
        ]:
            self.add_command(command)
          
    def _load_settings(self):
        if not os.path.exists(BOT_SETTINGS_FILE):
            return
        try:
            with open(BOT_SETTINGS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            log.exception('Failed to load bot settings')
            return

        if not isinstance(data, dict):
            return

        guilds = data.get('guilds')
        if isinstance(guilds, dict):
            self.settings['guilds'] = guilds
        else:
            self.settings['guilds'] = {}

        defaults = data.get('defaults', {})
        if not isinstance(defaults, dict):
            defaults = {}
          
        try:
            self.settings['defaults']['log_channel_id'] = int(defaults.get('log_channel_id', LOG_CHANNEL_ID) or LOG_CHANNEL_ID)
        except Exception:
            self.settings['defaults']['log_channel_id'] = LOG_CHANNEL_ID

        try:
            self.settings['defaults']['moderator_role_id'] = int(defaults.get('moderator_role_id', 0) or 0)
        except Exception:
            self.settings['defaults']['moderator_role_id'] = 0

        try:
            self.settings['defaults']['lockdown_role_id'] = int(defaults.get('lockdown_role_id', LOCKDOWN_ROLE_ID) or LOCKDOWN_ROLE_ID)
        except Exception:
            self.settings['defaults']['lockdown_role_id'] = LOCKDOWN_ROLE_ID

        try:
            self.settings['defaults']['ticket_staff_role_id'] = int(defaults.get('ticket_staff_role_id', TICKET_STAFF_ROLE_ID) or TICKET_STAFF_ROLE_ID)
        except Exception:
            self.settings['defaults']['ticket_staff_role_id'] = TICKET_STAFF_ROLE_ID

        try:
            self.settings['defaults']['quarantine_role_id'] = int(defaults.get('quarantine_role_id', QUARANTINE_ROLE_ID) or QUARANTINE_ROLE_ID)
        except Exception:
            self.settings['defaults']['quarantine_role_id'] = QUARANTINE_ROLE_ID

        try:
            self.settings['defaults']['auto_timeout_duration_days'] = int(defaults.get('auto_timeout_duration_days', AUTO_TIMEOUT_DURATION_DAYS) or AUTO_TIMEOUT_DURATION_DAYS)
        except Exception:
            self.settings['defaults']['auto_timeout_duration_days'] = AUTO_TIMEOUT_DURATION_DAYS

        # Backward compatibility for legacy flat settings
        if 'guilds' not in data:
            try:
                self.settings['defaults']['log_channel_id'] = int(data.get('log_channel_id', self.settings['defaults']['log_channel_id']) or self.settings['defaults']['log_channel_id'])
            except Exception:
                pass
            try:
                self.settings['defaults']['moderator_role_id'] = int(data.get('moderator_role_id', self.settings['defaults']['moderator_role_id']) or self.settings['defaults']['moderator_role_id'])
            except Exception:
                pass

    def _save_settings(self):
        try:
            with open(BOT_SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2)
        except Exception:
            log.exception('Failed to save bot settings')

    def _get_guild_settings(self, guild: discord.Guild):
        if guild is None:
            return {}
        guild_id = str(guild.id)
        guilds = self.settings.setdefault('guilds', {})
        if guild_id not in guilds or not isinstance(guilds[guild_id], dict):
            guilds[guild_id] = {}
        return guilds[guild_id]

    def _get_guild_setting(self, guild: discord.Guild, key: str, default=0):
        if guild is None:
            return default
        guild_settings = self._get_guild_settings(guild)
        value = guild_settings.get(key, self.settings.get('defaults', {}).get(key, default))
        try:
            return int(value) if value is not None else default
        except Excepion:
            return default

    def _set_guild_setting(self, guild: discord.Guild, key: str, value):
        if guild is None:
            return
        guild_settings = self._get_guild_settings(guild)
        guild_settings[key] = int(value) if value is not None else 0
        self._save_settings()

    def _get_log_channel_id(self, guild: discord.Guild = None) -> int:
        return self._get_guild_setting(guild, 'log_channel_id', LOG_CHANNEL_ID)

    def _get_moderator_role_id(self, guild: discord.Guild = None) -> int:
        return self._get_guild_setting(guild, 'moderator_role_id', 0)

    def _get_lockdown_role_id(self, guild: discord.Guild = None) -> int:
        return self._get_guild_setting(guild, 'lockdown_role_id', LOCKDOWN_ROLE_ID)

    def _get_ticket_staff_role_id(self, guild: discord.Guild = None) -> int:
        return self._get_guild_setting(guild, 'ticket_staff_role_id', TICKET_STAFF_ROLE_ID)

    def _get_quarantine_role_id(self, guild: discord.Guild = None) -> int:
        return self._get_guild_setting(guild, 'quarantine_role_id', QUARANTINE_ROLE_ID)

    def _get_auto_timeout_duration_days(self, guild: discord.Guild = None) -> int:
        return self._get_guild_setting(guild, 'auto_timeout_duration_days', AUTO_TIMEOUT_DURATION_DAYS)

    def _resolve_log_channel(self, guild: discord.Guild = None):
        channel_id = self._get_log_channel_id(guild)
        if channel_id <= 0:
            return None
        channel = self.get_channel(channel_id)
        if channel is None and guild is not None:
            channel = guild.get_channel(channel_id)
        return channel

    async def _send_embed_to_log_channel(self, embed: discord.Embed, guild: discord.Guild = None):
        log_channel = self._resolve_log_channel(guild=guild)
        if log_channel is None:
            return False
        try:
            await log_channel.send(embed=embed)
            return True
        except Exception:
            log.exception('Failed to send embed to configured log channel')
            return False

    async def _send_case_embed(self, case: dict):
        if not isinstance(case, dict):
            return

        guild = None
        guild_id = case.get('guild_id')
        if guild_id:
            try:
                guild = self.get_guild(int(guild_id))
            except Exception:
                guild = None

        embed = discord.Embed(
            title='🗃️ Moderation Case Logged',
            color=discord.Color.blue(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='Case ID', value=str(case.get('id', 'Unknown')), inline=True)
        embed.add_field(name='Type', value=str(case.get('type', 'Unknown')), inline=True)
        embed.add_field(name='Moderator', value=str(case.get('mod', 'Unknown'))[:1024], inline=False)
        embed.add_field(name='User', value=str(case.get('user', 'Unknown'))[:1024], inline=False)
        embed.add_field(name='Reason', value=str(case.get('reason', 'No reason'))[:1024], inline=False)
        await self._send_embed_to_log_channel(embed, guild=guild)

    async def _send_malicious_link_embed(self, message: discord.Message, links):
        if not links:
            return
        embed = discord.Embed(
            title='🚨 Malicious Link Logged',
            color=discord.Color.red(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='User', value=f'{message.author} ({message.author.id})', inline=False)
        embed.add_field(name='Channel', value=message.channel.mention if message.channel else 'Unknown', inline=False)
        embed.add_field(name='Detected URL(s)', value='\n'.join(str(link) for link in links[:10])[:1000], inline=False)
        await self._send_embed_to_log_channel(embed, guild=message.guild)

    @staticmethod
    def _serialize_overwrite(overwrite: discord.PermissionOverwrite):
        allow, deny = overwrite.pair()
        return {'allow': allow.value, 'deny': deny.value}

    @staticmethod
    def _deserialize_overwrite(data):
        if not isinstance(data, dict):
            return None
        try:
            allow = discord.Permissions(int(data.get('allow', 0)))
            deny = discord.Permissions(int(data.get('deny', 0)))
        except Exception:
            return None
        return discord.PermissionOverwrite.from_pair(allow, deny)

    @staticmethod
    def _is_onboarding_readable_error(exc: Exception) -> bool:
        if not isinstance(exc, discord.HTTPException):
            return False
        if getattr(exc, 'code', None) != 350003:
            return False
        return 'Onboarding channels must be readable by everyone' in str(exc)

    def _save_lockdown_state(self):
        try:
            with open(LOCKDOWN_STATE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.lockdown_state, f, indent=2)
        except Exception:
            log.exception('Failed to save lockdown state')

    def _load_lockdown_state(self):
        if not os.path.exists(LOCKDOWN_STATE_FILE):
            return
        try:
            with open(LOCKDOWN_STATE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            log.exception('Failed to load lockdown state')
            return

        if not isinstance(data, dict):
            return

        if any(key in data for key in ('active', 'temp_channel_id', 'info_message_id', 'locked_channel_ids', 'channel_overwrites')):
            # Legacy format: store as default state under a placeholder key
            self.lockdown_state = {'default': data}
            return

        self.lockdown_state = data

    def _get_lockdown_state(self, guild: discord.Guild):
        if guild is None:
            return {
                'active': False,
                'temp_channel_id': None,
                'info_message_id': None,
                'info_text': '',
                'locked_channel_ids': [],
                'channel_overwrites': {},
            }

        guild_id = str(guild.id)
        state = self.lockdown_state.setdefault(guild_id, {})
        if not isinstance(state, dict):
            state = {}
            self.lockdown_state[guild_id] = state

        state.setdefault('active', False)
        state.setdefault('temp_channel_id', None)
        state.setdefault('info_message_id', None)
        state.setdefault('info_text', '')
        state.setdefault('locked_channel_ids', [])
        state.setdefault('channel_overwrites', {})
        return state

    async def _restore_channel_from_lockdown(self, guild: discord.Guild, channel_id: int, lock_role: discord.Role):
        channel = guild.get_channel(channel_id)
        if channel is None:
            return False

        state = self._get_lockdown_state(guild)
        before = state.get('channel_overwrites', {}).get(str(channel_id), {})
        everyone_data = before.get('everyone') if isinstance(before, dict) else None
        role_data = before.get('role') if isinstance(before, dict) else None

        everyone_overwrite = self._deserialize_overwrite(everyone_data)
        role_overwrite = self._deserialize_overwrite(role_data)

        try:
            if everyone_overwrite is None:
                await channel.set_permissions(guild.default_role, overwrite=None, reason='Lockdown: unlock restore')
            else:
                await channel.set_permissions(guild.default_role, overwrite=everyone_overwrite, reason='Lockdown: unlock restore')

            if role_overwrite is None:
                await channel.set_permissions(lock_role, overwrite=None, reason='Lockdown: unlock restore')
            else:
                await channel.set_permissions(lock_role, overwrite=role_overwrite, reason='Lockdown: unlock restore')
        except Exception:
            log.exception('Failed to restore channel permissions for %s', channel_id)
            return False

        state['channel_overwrites'].pop(str(channel_id), None)
        state['locked_channel_ids'] = [cid for cid in state.get('locked_channel_ids', []) if cid != channel_id]
        if not state['locked_channel_ids']:
            state['active'] = False
        self.lockdown_state[str(guild.id)] = state
        self._save_lockdown_state()
        return True

    async def _create_locked_ticket_from_modal(self, interaction: discord.Interaction, title: str, description: str):
        guild = interaction.guild
        member = interaction.user
        if guild is None or not isinstance(member, discord.Member):
            return await interaction.response.send_message('⚠️ Tickets can only be created inside a server.', ephemeral=True)

        panel_channel = interaction.channel
        if panel_channel is None and TICKET_CHANNEL_ID:
            panel_channel = self.get_channel(TICKET_CHANNEL_ID)
        if panel_channel is None or not isinstance(panel_channel, discord.TextChannel):
            return await interaction.response.send_message('⚠️ Ticket channel is not configured correctly.', ephemeral=True)

        category = panel_channel.category
        existing = discord.utils.get(guild.text_channels, topic=f'ticket_owner:{member.id}')
        if existing:
            return await interaction.response.send_message(f'ℹ️ You already have an open ticket: {existing.mention}', ephemeral=True)

        safe_name = re.sub(r'[^a-z0-9-]+', '-', member.display_name.lower()).strip('-')
        safe_name = safe_name[:20] or f'user-{member.id}'
        channel_name = f'ticket-{safe_name}'

        overwrites = {
            guild.default_role: discord.PermissionOverwrite(view_channel=False),
            member: discord.PermissionOverwrite(view_channel=True, send_messages=False, read_message_history=True),
            guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True, manage_messages=True),
        }

        staff_role_id = self._get_ticket_staff_role_id(guild)
        staff_role = guild.get_role(staff_role_id) if staff_role_id > 0 else None
        if staff_role is not None:
            overwrites[staff_role] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)

        try:
            ticket_channel = await guild.create_text_channel(
                name=channel_name,
                category=category,
                topic=f'ticket_owner:{member.id}',
                overwrites=overwrites,
                reason=f'Ticket opened by {member}',
            )
        except Exception:
            log.exception('Failed to create ticket channel')
            return await interaction.response.send_message('⚠️ Failed to create ticket channel.', ephemeral=True)

        embed = discord.Embed(
            title='🎫 New Ticket (Locked)',
            description='This ticket is currently locked. A staff member must press **Open Ticket** before the user can send messages.',
            color=discord.Color.orange(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='User', value=f'{member} ({member.id})', inline=False)
        embed.add_field(name='Title', value=title[:1024], inline=False)
        embed.add_field(name='Description', value=description[:1024], inline=False)

        mention = f'<@&{staff_role.id}>' if staff_role is not None else '@here'
        await ticket_channel.send(content=f'{mention} New ticket created.', embed=embed, view=TicketOpenView(self))

        self._add_case('ticket_created', member, member, title, {'description': description, 'channel_id': ticket_channel.id})
        await interaction.response.send_message(f'✅ Ticket created: {ticket_channel.mention}', ephemeral=True)
 
    def _get_configured_role_ids(self, command_name: str):
        configured = COMMAND_ROLE_ACCESS.get(command_name, [])
        cleaned = []
        for role_id in configured:
            try:
                parsed = int(role_id)
            except Exception:
                continue
            if parsed > 0 and parsed not in cleaned:
                cleaned.append(parsed)
            if len(cleaned) >= MAX_ROLES_PER_COMMAND:
                break
        return cleaned

    def _has_fallback_permission(self, member: discord.Member, command_name: str) -> bool:
        perms = member.guild_permissions
        if command_name == 'ban':
            return perms.ban_members
        if command_name == 'unban':
            return perms.ban_members
        if command_name == 'kick':
            return perms.kick_members
        if command_name == 'timeout':
            return perms.moderate_members
        if command_name == 'verify':
            return perms.moderate_members
        if command_name == 'setautotimeout':
            return perms.manage_guild
        if command_name == 'delete':
            return perms.manage_messages
        if command_name == 'reply':
            return perms.manage_messages
        if command_name == 'cases':
            return perms.manage_messages
        if command_name == 'lastphish':
            return perms.manage_messages
        if command_name == 'ticketpanel':
            return perms.manage_messages
        if command_name == 'lockall':
            return perms.manage_channels
        if command_name == 'editlockmsg':
            return perms.manage_channels
        if command_name == 'unlock':
            return perms.manage_channels
        if command_name == 'unlockall':
            return perms.manage_channels
        return False

    async def _has_command_access(self, ctx, command_name: str) -> bool:
        if ctx.guild is None or not isinstance(ctx.author, discord.Member):
            return False

        if await self.is_owner(ctx.author):
            return True

        if ctx.author.guild_permissions.administrator:
            return True

        role_ids = self._get_configured_role_ids(command_name)
        if any(role.id in role_ids for role in ctx.author.roles):
            return True

        # Check moderator role for moderation commands
        moderator_role_id = self._get_moderator_role_id(ctx.guild)
        if moderator_role_id > 0:
            moderator_commands = {
                'ban', 'unban', 'kick', 'timeout', 'verify', 'delete', 'reply', 'cases', 'lastphish',
                'ticketpanel', 'lockall', 'editlockmsg', 'unlock', 'unlockall',
                'setlogchannel', 'setmoderatorrole', 'setlockdownrole',
                'setquarantinerole', 'setticketstaffrole', 'setautotimeout'
            }
            if command_name in moderator_commands and any(role.id == moderator_role_id for role in ctx.author.roles):
                return True

        if command_name == 'verify' and any(role.id == moderator_role_id for role in ctx.author.roles):
            return True

        return self._has_fallback_permission(ctx.author, command_name)

    def _make_command_access_check(self, command_name: str):
        async def predicate(ctx):
            return await self._has_command_access(ctx, command_name)
        return predicate 
      
    def _load_cases(self):
        if os.path.exists('cases.json'):
            try:
                with open('cases.json') as f:
                    self.case_records = json.load(f)
            except Exception:
                self.case_records = []

    def _save_cases(self):
        with open('cases.json','w') as f:
            json.dump(self.case_records, f, indent=2)
          
    def _load_custom_link_patterns(self):
        self.custom_link_patterns = []
        if not os.path.exists(CUSTOM_LINK_PATTERNS_FILE):
            return

        try:
            with open(CUSTOM_LINK_PATTERNS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            log.exception('Failed to load custom link patterns')
            return

        if not isinstance(data, list):
            return

        for item in data:
            if isinstance(item, str):
                link, pattern = '', item
            elif isinstance(item, dict):
                link = str(item.get('link', '')).strip()
                pattern = str(item.get('pattern', '')).strip()
            else:
                continue

            if not pattern:
                continue
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue

            self.custom_link_patterns.append({'link': link, 'pattern': pattern})

    def _save_custom_link_patterns(self):
        with open(CUSTOM_LINK_PATTERNS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.custom_link_patterns, f, indent=2)

    def _refresh_custom_phish_regex(self):
        global CUSTOM_PHISH_RE
        if not self.custom_link_patterns:
            CUSTOM_PHISH_RE = None
            return

        patterns = [entry.get('pattern', '') for entry in self.custom_link_patterns if isinstance(entry, dict)]
        patterns = [p for p in patterns if p]
        if not patterns:
            CUSTOM_PHISH_RE = None
            return

        combined = '|'.join(f'(?:{pattern})' for pattern in patterns)
        try:
            CUSTOM_PHISH_RE = re.compile(combined, re.IGNORECASE)
        except re.error:
            log.exception('Failed to compile custom phishing regex list')
            CUSTOM_PHISH_RE = None

    def _log_malicious_links(self, message: discord.Message, links):
        if not links:
            return

        entry = {
            'time': datetime.utcnow().isoformat(),
            'guild_id': message.guild.id if message.guild else None,
            'channel_id': message.channel.id if message.channel else None,
            'message_id': message.id,
            'user_id': message.author.id,
            'user': str(message.author),
            'links': links,
            'content': message.content,
        }

        try:
            with open(MALICIOUS_LINK_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        except Exception:
            log.exception('Failed to write malicious link log entry')

        try:
            asyncio.create_task(self._send_malicious_link_embed(message, links))
        except Exception:
            pass
          
    def _add_case(self, typ, user, mod, reason, extra=None):
        case={'id':len(self.case_records)+1,'type':typ,'user':str(user),'mod':str(mod),'reason':reason,'time':datetime.utcnow().isoformat()}
        if extra: case.update(extra)
        self.case_records.append(case)
        self._save_cases()
        try:
            asyncio.create_task(self._send_case_embed(case))
        except Exception:
            pass
        return case
    
    async def _quarantine_user(self, message, trigger: str, evidence: str = ''):
        if not message.guild or not isinstance(message.author, discord.Member):
            return False

        role_id = self._get_quarantine_role_id(message.guild)
        if role_id <= 0:
            log.warning('Quarantine role is not configured for guild %s', message.guild.id)
            return False

        role = message.guild.get_role(role_id)
        if role is None:
            log.warning('Quarantine role not found: %s for guild %s', role_id, message.guild.id)
            return False

        if role in message.author.roles:
            return False

        try:
            await message.author.add_roles(role, reason=f'Auto quarantine: {trigger}')
        except Exception:
            log.exception('Failed to assign quarantine role')
            return False

        self._add_case('quarantine', message.author, self.user, f'Auto quarantine: {trigger}', {'evidence': evidence})

        log_channel = self._resolve_log_channel(message.guild) or message.channel
        if log_channel is None:
            log_channel = message.channel

        embed = discord.Embed(
            title='🛑 User Quarantined',
            color=discord.Color.dark_orange(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='User', value=f'{message.author} ({message.author.id})', inline=False)
        embed.add_field(name='Role', value=f'{role.name} ({role.id})', inline=False)
        embed.add_field(name='Reason', value=trigger, inline=False)
        if evidence:
            embed.add_field(name='Evidence', value=evidence[:1000], inline=False)

        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

        return True

    def _is_suspected_spam_account(self, member: discord.Member) -> bool:
        if not isinstance(member, discord.Member):
            return False

        created = member.created_at.replace(tzinfo=None)
        age = datetime.utcnow() - created
        name_text = f'{member.name} {member.display_name}'.lower()

        if age <= timedelta(days=AUTO_TIMEOUT_NEW_ACCOUNT_DAYS):
            return True

        if age <= timedelta(days=30):
            if len(re.findall(r'\d', name_text)) >= 4:
                return True
            if any(term in name_text for term in ('free', 'nitro', 'gift', 'boost', 'giveaway', 'discordgift', 'discordnitro')):
                return True
            if member.avatar is None:
                return True

        return False

    async def _auto_timeout_spam_account(self, member: discord.Member) -> bool:
        if member.guild is None:
            return False

        duration = timedelta(days=self._get_auto_timeout_duration_days(member.guild))
        try:
            await member.timeout(duration, reason='Auto-timeout suspected spam account')
        except Exception:
            log.exception('Failed to time out suspected spam account: %s', member.id)
            return False

        age = datetime.utcnow() - member.created_at.replace(tzinfo=None)
        self._add_case(
            'auto_timeout_spam_account',
            member,
            self.user,
            'Auto-timeout suspected spam account',
            {'created_at': member.created_at.isoformat(), 'duration_days': self._get_auto_timeout_duration_days(member.guild)}
        )

        embed = discord.Embed(
            title='⚠️ Suspected Spam Account Timed Out',
            color=discord.Color.orange(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='User', value=f'{member} ({member.id})', inline=False)
        embed.add_field(name='Account Age', value=f'{age.days} day(s)', inline=False)
        embed.add_field(name='Reason', value='Account matched suspected spam heuristics', inline=False)

        try:
            await self._send_embed_to_log_channel(embed, guild=member.guild)
        except Exception:
            pass

        return True

    async def _handle_dm_ticket(self, message: discord.Message):
        try:
            await message.channel.send(
                '🎫 This bot now uses an in-server ticket system. Please use the **Create Ticket** button in the server ticket panel.'
            )
        except Exception:
            pass

    async def on_ready(self):
        log.info(f'Logged in as {self.user}')
        log.info('Loaded commands: %s', ', '.join(sorted(c.name for c in self.commands)))
        log.info('Loaded custom phishing patterns: %s', len(self.custom_link_patterns))
        log.info('Configured log channel ID: %s', self._get_log_channel_id())
        for cmd in sorted(COMMAND_ROLE_ACCESS.keys()):
            role_ids = self._get_configured_role_ids(cmd)
            if len(COMMAND_ROLE_ACCESS.get(cmd, [])) > MAX_ROLES_PER_COMMAND:
                log.warning('Only first %s role IDs are used for command "%s"', MAX_ROLES_PER_COMMAND, cmd)
            log.info('Access config for %s: roles=%s + fallback_perm=True', cmd, role_ids if role_ids else '[]') 
        await self.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name='Gone Phishin'))

    async def on_message(self, message):
        if message.author.bot: return

        if message.guild is None:
            await self._handle_dm_ticket(message)
            return

        if message.content.startswith(PREFIX):
            await self.process_commands(message)
            return

        token_match = detect_discord_token(message.content)
        if token_match:
            try: await message.delete()
            except: pass
            await self._quarantine_user(message, 'Bot token detected', f'{token_match.group(0)[:12]}...')

            token_embed = discord.Embed(
                title='🚨 Bot Token Caught',
                color=discord.Color.dark_red(),
                timestamp=datetime.utcnow()
            )
            token_embed.add_field(name='User', value=f'{message.author} ({message.author.id})', inline=False)
            token_embed.add_field(name='Channel', value=message.channel.mention, inline=False)
            token_embed.add_field(name='Token (masked)', value=f'`{token_match.group(0)[:12]}...`', inline=False)

            await self._send_embed_to_log_channel(token_embed, guild=message.guild)

            try:
                await message.channel.send('⚠️ Potential bot token removed for safety.', delete_after=10)
            except Exception:
                pass

            return await self.process_commands(message)

        urls = _extract_urls_for_analysis(message.content)
        bad = [u for u in urls if is_phish(u)]

        if bad:
            self._log_malicious_links(message, bad)
            try: await message.delete()
            except: pass
              
            evidence = 'URLs:\n' + '\n'.join(bad[:10])
            await self._quarantine_user(message, 'Malicious link detected in text', evidence[:1500])
            try:     
                await message.channel.send(
                    f'⚠️ Phishing removed: {" ".join(bad[:5])}',
                    delete_after=10,
                )
            except Exception:
                pass

            embed = discord.Embed(
                title='🚨 Phishing Link Caught',
                color=discord.Color.red(),
                timestamp=datetime.utcnow()
            )
            embed.add_field(name='User', value=f'{message.author} ({message.author.id})', inline=False)
            embed.add_field(name='Detected URL(s)', value='\n'.join(bad)[:1000], inline=False)
            embed.add_field(name='Channel', value=message.channel.mention, inline=False)
           
            await self._send_embed_to_log_channel(embed, guild=message.guild)
        await self.process_commands(message)

    async def on_member_join(self, member: discord.Member):
        if member.bot or member.guild is None:
            return

        if self._is_suspected_spam_account(member):
            timed_out = await self._auto_timeout_spam_account(member)
            if timed_out:
                try:
                    await member.send(
                        '⚠️ Your account has been temporarily timed out because it matched spam account protection criteria. '
                        'A staff member must verify you before the timeout is removed.'
                    )
                except Exception:
                    pass

    async def on_command_error(self, ctx, error):
        if hasattr(ctx.command, 'on_error'):
            return

        if isinstance(error, commands.CommandNotFound):
            return

        if isinstance(error, commands.NotOwner):
            await ctx.send('⛔ You are not allowed to use this command.')
            return

        if isinstance(error, commands.MissingPermissions):
            perms = ', '.join(error.missing_permissions)
            await ctx.send(f'⛔ You are missing permissions: {perms}')
            return

        if isinstance(error, commands.BotMissingPermissions):
            perms = ', '.join(error.missing_permissions)
            await ctx.send(f'⛔ I am missing permissions: {perms}')
            return

        if isinstance(error, commands.MissingRequiredArgument):
            await ctx.send(f'⚠️ Missing argument: {error.param.name}')
            return

        if isinstance(error, commands.BadArgument):
            await ctx.send('⚠️ Invalid argument provided.')
            return
          
        if isinstance(error, commands.CheckFailure):
            await ctx.send('⛔ You are not allowed to use this command.')
            return
          
        log.exception('Unhandled command error', exc_info=error)
        await ctx.send('⚠️ An unexpected error occurred while running that command.')

    async def check(self, ctx, *, text: str):
        urls = URL_RE.findall(text)
        if not urls:
            urls = [text.strip()]

        results = []
        for url in urls:
            status = '⚠️ Suspicious' if is_phish(url) else '✅ Looks safe'
            results.append(f'{status} - {url}')

        embed = discord.Embed(
            title='Link Check Result',
            description='\n'.join(results),
            color=discord.Color.orange(),
            timestamp=datetime.utcnow()
        )
        embed.set_footer(text=f'Checked by {ctx.author}')
        await ctx.send(embed=embed)

    async def cmd_help(self, ctx):
        embed = discord.Embed(
            title='Anti-Phish Bot Commands',
            color=discord.Color.blurple(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='DM Ticket', value='DMs are disabled for ticket intake. Use the server ticket panel button instead.', inline=False)
        embed.add_field(name=f'{PREFIX}ping', value='Quick command test (bot should reply Pong).', inline=False)
        embed.add_field(name=f'{PREFIX}check <text/link>', value='Check a link or text for suspicious/unsafe content.', inline=False)
        embed.add_field(name=f'{PREFIX}add_link <link>', value='Add a phishing link pattern for auto-detection.', inline=False)
        embed.add_field(name=f'{PREFIX}ban <member> [reason]', value='Ban a member.', inline=False)
        embed.add_field(name=f'{PREFIX}unban <user_id> [reason]', value='Unban a user by their ID.', inline=False)
        embed.add_field(name=f'{PREFIX}kick <member> [reason]', value='Kick a member.', inline=False)
        embed.add_field(name=f'{PREFIX}timeout <member> <duration> [reason]', value='Timeout format: 1d / 2h / 30m / 60s.', inline=False)
        embed.add_field(name=f'{PREFIX}clear [amount]', value='Delete 1-100 messages. Alias: delete.', inline=False)
        embed.add_field(name=f'{PREFIX}verify <member> [reason]', value='Remove a timeout from a verified member.', inline=False)
        embed.add_field(name=f'{PREFIX}reply <user_id> <message>', value='Reply to a user who opened a DM ticket.', inline=False)
        embed.add_field(name=f'{PREFIX}cases [member]', value='Show stored moderation cases.', inline=False)
        embed.add_field(name=f'{PREFIX}setlockdownrole [@role]', value='Set the role that lockdown commands will allow access to. Leave empty to clear.', inline=False)
        embed.add_field(name=f'{PREFIX}setquarantinerole [@role]', value='Set the role used for auto-quarantine assignments. Leave empty to clear.', inline=False)
        embed.add_field(name=f'{PREFIX}setticketstaffrole [@role]', value='Set the ticket staff role used for ticket panel access. Leave empty to clear.', inline=False)
        embed.add_field(name='Fun Commands', value=f'{PREFIX}trivia | {PREFIX}8ball <question> | {PREFIX}coinflip | {PREFIX}roll [sides] | {PREFIX}rps <rock/paper/scissors>', inline=False)
        embed.add_field(name=f'{PREFIX}setlogchannel [#channel]', value='Set the channel used for embed logs (cases and phishing/security events).', inline=False)
        embed.add_field(name=f'{PREFIX}lastphish', value='Show the most recent malicious-link log entry.', inline=False)
        embed.add_field(name=f'{PREFIX}setmoderatorrole [@role]', value='Set a moderator role that can use most moderation commands. Leave empty to clear.', inline=False)
        embed.add_field(name=f'{PREFIX}ticketpanel', value='Post the ticket panel with a Create Ticket button (staff only).', inline=False)
        embed.add_field(name=f'{PREFIX}setautotimeout [days]', value='Set the auto-timeout duration for suspected spam accounts. Leave empty to clear guild override.', inline=False)
        embed.add_field(name=f'{PREFIX}announce [#channel] <message>', value='Owner-only announcement command.', inline=False)
        embed.add_field(name=f'{PREFIX}lockall [message]', value='Lock all channels to lockdown role and create/update a temporary status channel.', inline=False)
        embed.add_field(name=f'{PREFIX}editlockmsg <message>', value='Edit the lockdown status message in the temporary channel.', inline=False)
        embed.add_field(name=f'{PREFIX}unlock [channel_id]', value='Unlock one channel (defaults to current channel).', inline=False)
        embed.add_field(name=f'{PREFIX}unlockall', value='Unlock all locked channels and delete the temporary status channel.', inline=False)
        embed.add_field(name='Ticket Buttons', value='Staff can use Open Ticket and Close Ticket buttons inside each ticket channel.', inline=False)
        await ctx.send(embed=embed)
      
    async def setlogchannel(self, ctx, channel: discord.TextChannel = None):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        target = channel if channel is not None else ctx.channel
        if not isinstance(target, discord.TextChannel):
            return await ctx.send('⚠️ Please choose a text channel.')

        self._set_guild_setting(guild, 'log_channel_id', target.id)
        await ctx.send(f'✅ Log channel set to {target.mention}. New log events will be sent there as embeds.')

    async def setmoderatorrole(self, ctx, role: discord.Role = None):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        if role is None:
            self._set_guild_setting(guild, 'moderator_role_id', 0)
            await ctx.send('✅ Moderator role cleared. Only users with Discord moderation permissions or administrator role can use moderation commands.')
        else:
            self._set_guild_setting(guild, 'moderator_role_id', role.id)
            await ctx.send(f'✅ Moderator role set to {role.mention}. Users with this role can now use most moderation commands.')

    async def setlockdownrole(self, ctx, role: discord.Role = None):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        if role is None:
            self._set_guild_setting(guild, 'lockdown_role_id', 0)
            await ctx.send('✅ Lockdown role cleared. Lockdown commands will no longer work until a role is configured.')
        else:
            self._set_guild_setting(guild, 'lockdown_role_id', role.id)
            await ctx.send(f'✅ Lockdown role set to {role.mention}. Lockdown commands will use this role.')

    async def setquarantinerole(self, ctx, role: discord.Role = None):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        if role is None:
            self._set_guild_setting(guild, 'quarantine_role_id', 0)
            await ctx.send('✅ Quarantine role cleared. Auto-quarantine will be disabled until a role is configured.')
        else:
            self._set_guild_setting(guild, 'quarantine_role_id', role.id)
            await ctx.send(f'✅ Quarantine role set to {role.mention}. Auto-quarantine will use this role.')

    async def setautotimeout(self, ctx, days: int = None):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        if days is None:
            self._set_guild_setting(guild, 'auto_timeout_duration_days', AUTO_TIMEOUT_DURATION_DAYS)
            await ctx.send(f'✅ Auto-timeout duration cleared. Using default: {AUTO_TIMEOUT_DURATION_DAYS} days.')
            return

        if days < 1 or days > 90:
            return await ctx.send('⚠️ Provide a duration between 1 and 90 days.')

        self._set_guild_setting(guild, 'auto_timeout_duration_days', days)
        await ctx.send(f'✅ Auto-timeout duration set to {days} day(s) for suspected spam accounts.')

    async def announce(self, ctx, channel: discord.TextChannel = None, *, text: str):
        if channel is None:
            channel = ctx.channel
        if channel is None or not isinstance(channel, discord.TextChannel):
            return await ctx.send('⚠️ Please provide a valid text channel or use this command in a text channel.')

        announce_embed = discord.Embed(
            title='📢 Announcement',
            description=text,
            color=discord.Color.blurple(),
            timestamp=datetime.utcnow()
        )
        announce_embed.set_footer(text=f'Announcement by {ctx.author}')

        try:
            await channel.send(embed=announce_embed)
        except Exception:
            return await ctx.send('⚠️ Failed to send announcement to that channel.')

        await ctx.send(f'✅ Announcement sent to {channel.mention}.')

    async def setticketstaffrole(self, ctx, role: discord.Role = None):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        if role is None:
            self._set_guild_setting(guild, 'ticket_staff_role_id', 0)
            await ctx.send('✅ Ticket staff role cleared. Ticket panels will no longer auto-grant staff access unless a role is configured.')
        else:
            self._set_guild_setting(guild, 'ticket_staff_role_id', role.id)
            await ctx.send(f'✅ Ticket staff role set to {role.mention}. Tickets will grant this role access.')
    
    async def lockall(self, ctx, *, message: str = None):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        lock_role_id = self._get_lockdown_role_id(guild)
        if lock_role_id <= 0:
            return await ctx.send('⚠️ Lockdown role is not configured for this server.')

        lock_role = guild.get_role(lock_role_id)
        if lock_role is None:
            return await ctx.send(f'⚠️ Lockdown role not found: {lock_role_id}')

        info_text = (message or '').strip() or '🔒 This server is temporarily locked down. Please wait while staff resolve an ongoing issue.'
        
        guild_state = self._get_lockdown_state(guild)
        temp_channel = None
        temp_channel_id = guild_state.get('temp_channel_id')
        if temp_channel_id:
            temp_channel = guild.get_channel(int(temp_channel_id))

        if temp_channel is None:
            temp_overwrites = {
                guild.default_role: discord.PermissionOverwrite(view_channel=True, send_messages=False, read_message_history=True),
                lock_role: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
                guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True, manage_messages=True),
            }
            try:
                temp_channel = await guild.create_text_channel(
                    name='server-status',
                    overwrites=temp_overwrites,
                    reason=f'Lockdown initiated by {ctx.author}',
                )
            except Exception:
                log.exception('Failed to create temporary lockdown channel')
                return await ctx.send('⚠️ Failed to create the temporary lockdown channel.')

        locked_ids = set(guild_state.get('locked_channel_ids', []))
        channel_overwrites = guild_state.get('channel_overwrites', {})
        changed = 0
        skipped_onboarding = []

        for channel in guild.channels:
            if channel.id == temp_channel.id:
                continue

            if channel.id in locked_ids:
                continue

            previous_everyone = channel.overwrites_for(guild.default_role)
            previous_role = channel.overwrites_for(lock_role)
            channel_overwrites[str(channel.id)] = {
                'everyone': self._serialize_overwrite(previous_everyone),
                'role': self._serialize_overwrite(previous_role),
            }

            try:
                await channel.set_permissions(guild.default_role, view_channel=False, reason=f'Lockdown initiated by {ctx.author}')
                await channel.set_permissions(lock_role, view_channel=True, reason=f'Lockdown initiated by {ctx.author}')
            except Exception as exc:
                channel_overwrites.pop(str(channel.id), None)
                if self._is_onboarding_readable_error(exc):
                    skipped_onboarding.append(channel)
                    log.warning('Skipped onboarding channel %s (%s) during lockdown', channel.id, getattr(channel, 'name', 'unknown'))
                    continue
                log.exception('Failed to lock channel %s', channel.id)
                continue

            locked_ids.add(channel.id)
            changed += 1

        status_embed = discord.Embed(
            title='🔒 Temporary Server Lockdown',
            description=info_text,
            color=discord.Color.dark_red(),
            timestamp=datetime.utcnow(),
        )
        status_embed.add_field(name='Access', value=f'Only <@&{lock_role_id}> can access most channels right now.', inline=False)
        status_embed.set_footer(text=f'Actioned by {ctx.author}')

        info_message_id = guild_state.get('info_message_id')
        if info_message_id:
            try:
                old_msg = await temp_channel.fetch_message(int(info_message_id))
                await old_msg.edit(embed=status_embed)
                status_msg = old_msg
            except Exception:
                status_msg = await temp_channel.send(embed=status_embed)
        else:
            status_msg = await temp_channel.send(embed=status_embed)

        guild_state['active'] = True
        guild_state['temp_channel_id'] = temp_channel.id
        guild_state['info_message_id'] = status_msg.id
        guild_state['info_text'] = info_text
        guild_state['locked_channel_ids'] = sorted(locked_ids)
        guild_state['channel_overwrites'] = channel_overwrites
        self.lockdown_state[str(guild.id)] = guild_state
        self._save_lockdown_state()

        self._add_case('lockdown_all', guild.name, ctx.author, f'Locked {changed} channels', {'temp_channel_id': temp_channel.id})
        if skipped_onboarding:
            skipped_text = ', '.join(ch.mention for ch in skipped_onboarding[:10])
            extra = ''
            if len(skipped_onboarding) > 10:
                extra = f' (+{len(skipped_onboarding) - 10} more)'
            await ctx.send(
                f'🔒 Lockdown active. Updated {changed} channel(s). Status channel: {temp_channel.mention}\n'
                f'⚠️ Skipped onboarding-only channel(s): {skipped_text}{extra}'
            )
        else:
            await ctx.send(f'🔒 Lockdown active. Updated {changed} channel(s). Status channel: {temp_channel.mention}')

    async def editlockmsg(self, ctx, *, message: str):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        guild_state = self._get_lockdown_state(guild)
        temp_channel_id = guild_state.get('temp_channel_id')
        info_message_id = guild_state.get('info_message_id')
        if not temp_channel_id:
            return await ctx.send('⚠️ No lockdown status channel is currently tracked.')

        temp_channel = guild.get_channel(int(temp_channel_id))
        if temp_channel is None or not isinstance(temp_channel, discord.TextChannel):
            return await ctx.send('⚠️ The lockdown status channel no longer exists.')

        text = message.strip()
        if not text:
            return await ctx.send('⚠️ Provide a non-empty message.')

        lock_role_id = self._get_lockdown_role_id(guild)
        embed = discord.Embed(
            title='🔒 Temporary Server Lockdown',
            description=text,
            color=discord.Color.dark_red(),
            timestamp=datetime.utcnow(),
        )
        embed.add_field(name='Access', value=f'Only <@&{lock_role_id}> can access most channels right now.', inline=False)
        embed.set_footer(text=f'Updated by {ctx.author}')

        try:
            if info_message_id:
                status_msg = await temp_channel.fetch_message(int(info_message_id))
                await status_msg.edit(embed=embed)
            else:
                status_msg = await temp_channel.send(embed=embed)
        except Exception:
            log.exception('Failed to update lockdown message')
            return await ctx.send('⚠️ Failed to edit the lockdown message.')

        guild_state['info_message_id'] = status_msg.id
        guild_state['info_text'] = text
        self.lockdown_state[str(guild.id)] = guild_state
        self._save_lockdown_state()
        await ctx.send('✅ Lockdown status message updated.')

    async def unlock(self, ctx, channel_id: int = None):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        lock_role_id = self._get_lockdown_role_id(guild)
        if lock_role_id <= 0:
            return await ctx.send('⚠️ Lockdown role is not configured for this server.')

        lock_role = guild.get_role(lock_role_id)
        if lock_role is None:
            return await ctx.send(f'⚠️ Lockdown role not found: {lock_role_id}')

        guild_state = self._get_lockdown_state(guild)
        target_channel = ctx.channel if channel_id is None else guild.get_channel(channel_id)
        if target_channel is None:
            return await ctx.send('⚠️ Channel not found.')

        if guild_state.get('temp_channel_id') == target_channel.id:
            return await ctx.send('⚠️ Use unlockall to remove the temporary status channel.')

        ok = await self._restore_channel_from_lockdown(guild, target_channel.id, lock_role)
        if not ok:
            return await ctx.send('⚠️ Failed to unlock that channel or channel was not tracked as locked.')

        self._add_case('unlock_single', str(target_channel), ctx.author, 'Unlocked single channel', {'channel_id': target_channel.id})
        await ctx.send(f'🔓 Unlocked channel: {target_channel.mention}')

    async def unlockall(self, ctx):
        guild = ctx.guild
        if guild is None:
            return await ctx.send('⚠️ This command can only be used in a server.')

        lock_role_id = self._get_lockdown_role_id(guild)
        if lock_role_id <= 0:
            return await ctx.send('⚠️ Lockdown role is not configured for this server.')

        lock_role = guild.get_role(lock_role_id)
        if lock_role is None:
            return await ctx.send(f'⚠️ Lockdown role not found: {lock_role_id}')

        guild_state = self._get_lockdown_state(guild)
        locked_ids = list(guild_state.get('locked_channel_ids', []))
        restored = 0
        for channel_id in locked_ids:
            if await self._restore_channel_from_lockdown(guild, int(channel_id), lock_role):
                restored += 1

        temp_channel_id = guild_state.get('temp_channel_id')
        temp_channel = guild.get_channel(int(temp_channel_id)) if temp_channel_id else None

        guild_state['active'] = False
        guild_state['locked_channel_ids'] = []
        guild_state['channel_overwrites'] = {}
        guild_state['info_message_id'] = None
        guild_state['info_text'] = ''
        guild_state['temp_channel_id'] = None
        self.lockdown_state[str(guild.id)] = guild_state

        deleted_temp = False
        if temp_channel is not None:
            try:
                await temp_channel.delete(reason=f'Lockdown ended by {ctx.author}')
                deleted_temp = True
            except Exception:
                log.exception('Failed to delete temporary lockdown channel')

        self._save_lockdown_state()

        self._add_case('unlock_all', guild.name, ctx.author, f'Unlocked {restored} channels', {'deleted_temp_channel': deleted_temp})
        if deleted_temp:
            await ctx.send(f'🔓 Unlock complete. Restored {restored} channel(s) and removed the temporary status channel.')
        else:
            await ctx.send(f'🔓 Unlock complete. Restored {restored} channel(s). Temporary status channel was not deleted.')

    async def ticketpanel(self, ctx):
        if self.ticket_panel_view is None:
            self.ticket_panel_view = TicketPanelView(self)
            self.add_view(self.ticket_panel_view)

        panel_channel = ctx.channel
        if panel_channel is None or not isinstance(panel_channel, discord.TextChannel):
            return await ctx.send('⚠️ Ticket channel is not configured correctly.')

        embed = discord.Embed(
            title='🎫 Support Tickets',
            description='Press **Create Ticket** to open a support ticket. You will provide a title and description, then staff will unlock your ticket.',
            color=discord.Color.blurple(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='How it works', value='1) Press the button\n2) Fill in title and description\n3) Wait for staff to open the ticket', inline=False)
        await panel_channel.send(embed=embed, view=self.ticket_panel_view)

    async def cmdhelp(self, ctx):
        await self.cmd_help(ctx)
      
    async def ping(self, ctx):
        await ctx.send('🏓 Pong!')

    async def ban(self, ctx, member: discord.Member, *, reason='No reason'):
        await ctx.guild.ban(member, reason=reason)
        self._add_case('ban', member, ctx.author, reason)
        await ctx.send(f'✅ {member} banned')

    async def unban(self, ctx, user_id: int, *, reason='No reason'):
        try:
            user = await self.fetch_user(user_id)
        except discord.NotFound:
            return await ctx.send('⚠️ User not found.')
        except discord.HTTPException:
            return await ctx.send('⚠️ Failed to fetch user information.')

        try:
            await ctx.guild.unban(user, reason=reason)
        except discord.NotFound:
            return await ctx.send('⚠️ User is not banned.')
        except discord.Forbidden:
            return await ctx.send('⚠️ I do not have permission to unban users.')
        except discord.HTTPException:
            return await ctx.send('⚠️ Failed to unban user.')

        self._add_case('unban', user, ctx.author, reason)
        await ctx.send(f'✅ {user} unbanned')

    async def kick(self, ctx, member: discord.Member, *, reason='No reason'):
        await ctx.guild.kick(member, reason=reason)
        self._add_case('kick', member, ctx.author, reason)
        await ctx.send(f'✅ {member} kicked')

    async def timeout(self, ctx, member: discord.Member, duration: str, *, reason='No reason'):
        dur = self._parse_duration(duration)
        if dur is None:
            return await ctx.send('Invalid duration. Use 1d/2h/30m/60s')
        await member.timeout(dur, reason=reason)
        self._add_case('timeout', member, ctx.author, reason, {'duration':duration})
        await ctx.send(f'✅ {member} timed out for {duration}')

    async def verify(self, ctx, member: discord.Member, *, reason='Verified by staff'):
        try:
            await member.timeout(None, reason=reason)
        except discord.Forbidden:
            return await ctx.send('⚠️ I do not have permission to remove the timeout for that member.')
        except Exception:
            log.exception('Failed to remove timeout for verified member')
            return await ctx.send('⚠️ Failed to remove the timeout for that member.')

        self._add_case('verify', member, ctx.author, reason)
        await ctx.send(f'✅ {member.mention} has been verified and timeout removed.')

    async def delete(self, ctx, amount: int = 5):
        amt = max(1, min(100, amount))
        await ctx.channel.purge(limit=amt)
        self._add_case('delete', 'system', ctx.author, f'deleted {amt}')
        msg=await ctx.send(f'✅ Deleted {amt} messages')
        await msg.delete(delay=5)

    async def add_link(self, ctx, *, link: str):
        normalized_link, pattern = _build_phish_pattern_from_link(link)
        if not normalized_link or not pattern:
            return await ctx.send('⚠️ Please provide a valid link or domain. Example: `=add_link bad-domain.com/login`')

        existing = [item.get('pattern') for item in self.custom_link_patterns if isinstance(item, dict)]
        if pattern in existing:
            return await ctx.send('ℹ️ That phishing link pattern is already in the detection list.')

        self.custom_link_patterns.append(
            {
                'link': normalized_link,
                'pattern': pattern,
                'added_by': ctx.author.id,
                'added_at': datetime.utcnow().isoformat(),
            }
        )
        self._save_custom_link_patterns()
        self._refresh_custom_phish_regex()

        self._add_case(
            'add_link',
            ctx.author,
            ctx.author,
            f'Added phishing link pattern: {normalized_link}',
            {'pattern': pattern}
        )
        await ctx.send(f'✅ Added phishing pattern for `{normalized_link}`. Future matching links will be auto-flagged.')

    async def cases(self, ctx, member: discord.Member=None):
        if member is None: member = ctx.author
        cs=[c for c in self.case_records if c['user'].startswith(str(member))]
        if not cs: return await ctx.send('No cases found')
        lines=[f"{c['id']}: {c['type']} {c['reason']} ({c['time']})" for c in cs]
        await ctx.send(f'Cases for {member}:\n' + '\n'.join(lines))

    async def reply(self, ctx, user_id: int, *, text: str):
        try:
            user = await self.fetch_user(user_id)
        except Exception:
            return await ctx.send('⚠️ Could not find that user ID.')

        embed = discord.Embed(
            title='📩 Staff Reply',
            description=text,
            color=discord.Color.green(),
            timestamp=datetime.utcnow()
        )
        embed.set_footer(text=f'Replied by {ctx.author}')

        try:
            await user.send(embed=embed)
        except discord.Forbidden:
            return await ctx.send('⚠️ Could not DM that user (DMs may be disabled).')
        except Exception:
            return await ctx.send('⚠️ Failed to send reply due to an unexpected error.')

        self._add_case('ticket_reply', user, ctx.author, text)
        await ctx.send(f'✅ Reply sent to {user} ({user.id})')

    async def lastphish(self, ctx):
        if not os.path.exists(MALICIOUS_LINK_LOG_FILE):
            return await ctx.send('No malicious-link logs found yet.')

        last_line = ''
        try:
            with open(MALICIOUS_LINK_LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        last_line = line.strip()
        except Exception:
            log.exception('Failed to read malicious link log file')
            return await ctx.send('⚠️ Failed to read the malicious-link log file.')

        if not last_line:
            return await ctx.send('No malicious-link logs found yet.')

        try:
            entry = json.loads(last_line)
        except Exception:
            return await ctx.send('⚠️ Last malicious-link log entry is invalid JSON.')

        links = entry.get('links', [])
        if isinstance(links, list):
            links_text = '\n'.join(str(link) for link in links[:10]) or '(none)'
        else:
            links_text = str(links)

        embed = discord.Embed(
            title='📄 Last Malicious Link Log',
            color=discord.Color.orange(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='Time (UTC)', value=str(entry.get('time', 'Unknown')), inline=False)
        embed.add_field(name='User', value=f"{entry.get('user', 'Unknown')} ({entry.get('user_id', 'Unknown')})", inline=False)
        embed.add_field(name='Channel ID', value=str(entry.get('channel_id', 'Unknown')), inline=False)
        embed.add_field(name='Link(s)', value=links_text[:1000], inline=False)
        embed.add_field(name='Message', value=str(entry.get('content', '(no content)'))[:1000], inline=False)
        await ctx.send(embed=embed)
      
    @staticmethod
    def _parse_duration(s):
        s=s.lower().strip()
        try:
            if s.endswith('d'): return timedelta(days=int(s[:-1]))
            if s.endswith('h'): return timedelta(hours=int(s[:-1]))
            if s.endswith('m'): return timedelta(minutes=int(s[:-1]))
            if s.endswith('s'): return timedelta(seconds=int(s[:-1]))
        except Exception:
            pass
        return None


def main():
    if not TOKEN:
        log.error('Set BOT_TOKEN environment variable before running the bot')
        return
    bot = Bot()
    bot.run(TOKEN)

if __name__ == '__main__':
    main()


