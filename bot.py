import os, re, json, logging, random, html, asyncio
from urllib import request
from datetime import datetime, timedelta
import discord
from discord.ext import commands

TOKEN = "Paste your bot token here"
PREFIX = '='
LOG_CHANNEL_ID = 0
TICKET_CHANNEL_ID = 0
TICKET_STAFF_ROLE_ID = 1443345576832925888
QUARANTINE_ROLE_ID = 0
MALICIOUS_LINK_LOG_FILE = 'malicious_links.log'
CUSTOM_LINK_PATTERNS_FILE = 'custom_link_patterns.json'
CUSTOM_PHISH_RE = None

# Command role access (up to 8 role IDs per command).
# Add role IDs to allow those roles to use the command through the bot.
# Example: 'ban': [111111111111111111, 222222222222222222]
COMMAND_ROLE_ACCESS = {
    'ban': [],
    'kick': [],
    'timeout': [],
    'delete': [],
    'reply': [],
    'cases': [],
    'lastphish': [],
    'ticketpanel': [],
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
    # Normalize spaced separators so obfuscated links in text are still parsed.
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
        self.trivia_scores = {}
        self.custom_link_patterns = []
        self.ticket_panel_view = None
        self.ticket_open_view = None
        self._load_cases()
        self._load_trivia_scores()
        self._load_custom_link_patterns()
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

        async def ban_callback(ctx, member: discord.Member, *, reason='No reason'):
            await self.ban(ctx, member, reason=reason)

        async def kick_callback(ctx, member: discord.Member, *, reason='No reason'):
            await self.kick(ctx, member, reason=reason)

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
          
        async def trivia_callback(ctx):
            await self.trivia(ctx)

        async def eightball_callback(ctx, *, question: str):
            await self.eightball(ctx, question=question)

        async def coinflip_callback(ctx):
            await self.coinflip(ctx)

        async def roll_callback(ctx, sides: int = 6):
            await self.roll(ctx, sides=sides)

        async def rps_callback(ctx, choice: str):
            await self.rps(ctx, choice=choice)

        async def add_link_callback(ctx, *, link: str):
            await self.add_link(ctx, link=link)

        async def ticketpanel_callback(ctx):
            await self.ticketpanel(ctx)
          
        check_cmd = commands.Command(check_callback, name='check')
        check_cmd.add_check(commands.is_owner().predicate)

        help_cmd = commands.Command(help_callback, name='help')
        ping_cmd = commands.Command(ping_callback, name='ping')

        ban_cmd = commands.Command(ban_callback, name='ban')
        ban_cmd.add_check(self._make_command_access_check('ban'))

        kick_cmd = commands.Command(kick_callback, name='kick')
        kick_cmd.add_check(self._make_command_access_check('kick'))

        timeout_cmd = commands.Command(timeout_callback, name='timeout')
        timeout_cmd.add_check(self._make_command_access_check('timeout'))

        delete_cmd = commands.Command(delete_callback, name='delete', aliases=['clear'])
        delete_cmd.add_check(self._make_command_access_check('delete'))

        cases_cmd = commands.Command(cases_callback, name='cases')
        cases_cmd.add_check(self._make_command_access_check('cases'))

        reply_cmd = commands.Command(reply_callback, name='reply')
        reply_cmd.add_check(self._make_command_access_check('reply'))

        trivia_cmd = commands.Command(trivia_callback, name='trivia')
        eightball_cmd = commands.Command(eightball_callback, name='8ball')
        coinflip_cmd = commands.Command(coinflip_callback, name='coinflip')
        roll_cmd = commands.Command(roll_callback, name='roll')
        rps_cmd = commands.Command(rps_callback, name='rps')
        add_link_cmd = commands.Command(add_link_callback, name='add_link', aliases=['addlink'])
        ticketpanel_cmd = commands.Command(ticketpanel_callback, name='ticketpanel')
        ticketpanel_cmd.add_check(self._make_command_access_check('ticketpanel'))

        lastphish_cmd = commands.Command(lastphish_callback, name='lastphish')
        lastphish_cmd.add_check(self._make_command_access_check('lastphish'))

        for command in [
            check_cmd, help_cmd, ping_cmd, ban_cmd, kick_cmd, timeout_cmd,
            delete_cmd, cases_cmd, reply_cmd, lastphish_cmd, trivia_cmd, eightball_cmd,
            coinflip_cmd, roll_cmd, rps_cmd, add_link_cmd, ticketpanel_cmd
        ]:
            self.add_command(command)

    async def _create_locked_ticket_from_modal(self, interaction: discord.Interaction, title: str, description: str):
        guild = interaction.guild
        member = interaction.user
        if guild is None or not isinstance(member, discord.Member):
            return await interaction.response.send_message('⚠️ Tickets can only be created inside a server.', ephemeral=True)

        panel_channel = self.get_channel(TICKET_CHANNEL_ID) if TICKET_CHANNEL_ID else interaction.channel
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

        staff_role = guild.get_role(TICKET_STAFF_ROLE_ID)
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

        mention = f'<@&{TICKET_STAFF_ROLE_ID}>' if staff_role is not None else '@here'
        await ticket_channel.send(content=f'{mention} New ticket created.', embed=embed, view=TicketOpenView(self))

        self._add_case('ticket_created', member, member, title, {'description': description, 'channel_id': ticket_channel.id})
        await interaction.response.send_message(f'✅ Ticket created: {ticket_channel.mention}', ephemeral=True)

    async def _fetch_trivia_questions(self, amount: int = 10):
        url = f'https://opentdb.com/api.php?amount={amount}&type=multiple'

        def _load():
            with request.urlopen(url, timeout=12) as resp:
                payload = json.loads(resp.read().decode('utf-8'))
                return payload.get('results', [])

        try:
            return await asyncio.to_thread(_load)
        except Exception:
            log.exception('Failed to fetch trivia questions')
            return []
 
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
        if command_name == 'kick':
            return perms.kick_members
        if command_name == 'timeout':
            return perms.moderate_members
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
          
    def _load_trivia_scores(self):
        if os.path.exists('trivia_scores.json'):
            try:
                with open('trivia_scores.json') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self.trivia_scores = data
            except Exception:
                self.trivia_scores = {}

    def _save_trivia_scores(self):
        with open('trivia_scores.json', 'w') as f:
            json.dump(self.trivia_scores, f, indent=2)

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

    def _update_trivia_leaderboard(self, user: discord.abc.User, correct: bool):
        uid = str(user.id)
        entry = self.trivia_scores.get(uid)
        if not isinstance(entry, dict):
            entry = {
                'name': str(user),
                'correct': 0,
                'answered': 0,
            }

        entry['name'] = str(user)
        entry['answered'] = int(entry.get('answered', 0)) + 1
        if correct:
            entry['correct'] = int(entry.get('correct', 0)) + 1
        else:
            entry['correct'] = int(entry.get('correct', 0))

        self.trivia_scores[uid] = entry
        self._save_trivia_scores()

    def _format_trivia_leaderboard(self, limit: int = 5):
        rows = []
        for uid, data in self.trivia_scores.items():
            if not isinstance(data, dict):
                continue
            correct = int(data.get('correct', 0))
            answered = int(data.get('answered', 0))
            name = str(data.get('name', uid))
            accuracy = int((correct / answered) * 100) if answered > 0 else 0
            rows.append((correct, accuracy, answered, name))

        rows.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
        top = rows[:max(1, limit)]
        if not top:
            return 'No trivia scores yet.'

        lines = []
        for i, (correct, accuracy, answered, name) in enumerate(top, start=1):
            lines.append(f'{i}. {name} — {correct} correct / {answered} answered ({accuracy}%)')
        return '\n'.join(lines)
      
    def _add_case(self, typ, user, mod, reason, extra=None):
        case={'id':len(self.case_records)+1,'type':typ,'user':str(user),'mod':str(mod),'reason':reason,'time':datetime.utcnow().isoformat()}
        if extra: case.update(extra)
        self.case_records.append(case)
        self._save_cases()
        return case
    
    async def _quarantine_user(self, message, trigger: str, evidence: str = ''):
        if not message.guild or not isinstance(message.author, discord.Member):
            return False

        role = message.guild.get_role(QUARANTINE_ROLE_ID)
        if role is None:
            log.warning('Quarantine role not found: %s', QUARANTINE_ROLE_ID)
            return False

        if role in message.author.roles:
            return False

        try:
            await message.author.add_roles(role, reason=f'Auto quarantine: {trigger}')
        except Exception:
            log.exception('Failed to assign quarantine role')
            return False

        self._add_case('quarantine', message.author, self.user, f'Auto quarantine: {trigger}', {'evidence': evidence})

        log_channel = self.get_channel(LOG_CHANNEL_ID) if LOG_CHANNEL_ID else message.channel
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

            log_channel = self.get_channel(LOG_CHANNEL_ID) if LOG_CHANNEL_ID else message.channel
            if log_channel is None:
                log_channel = message.channel

            token_embed = discord.Embed(
                title='🚨 Bot Token Caught',
                color=discord.Color.dark_red(),
                timestamp=datetime.utcnow()
            )
            token_embed.add_field(name='User', value=f'{message.author} ({message.author.id})', inline=False)
            token_embed.add_field(name='Channel', value=message.channel.mention, inline=False)
            token_embed.add_field(name='Token (masked)', value=f'`{token_match.group(0)[:12]}...`', inline=False)

            try:
                await log_channel.send(embed=token_embed)
            except Exception:
                pass

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
              
            log_channel = None
            if LOG_CHANNEL_ID:
                log_channel = self.get_channel(LOG_CHANNEL_ID)
            if log_channel is None:
                log_channel = message.channel

            embed = discord.Embed(
                title='🚨 Phishing Link Caught',
                color=discord.Color.red(),
                timestamp=datetime.utcnow()
            )
            embed.add_field(name='User', value=f'{message.author} ({message.author.id})', inline=False)
            embed.add_field(name='Detected URL(s)', value='\n'.join(bad)[:1000], inline=False)
            embed.add_field(name='Channel', value=message.channel.mention, inline=False)

            try:
                await log_channel.send(embed=embed)
            except Exception:
                pass
        await self.process_commands(message)

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
        embed.add_field(name=f'{PREFIX}check <text/link>', value='Owner-only manual check for suspicious links.', inline=False)
        embed.add_field(name=f'{PREFIX}ban <member> [reason]', value='Ban a member.', inline=False)
        embed.add_field(name=f'{PREFIX}kick <member> [reason]', value='Kick a member.', inline=False)
        embed.add_field(name=f'{PREFIX}timeout <member> <duration> [reason]', value='Timeout format: 1d / 2h / 30m / 60s.', inline=False)
        embed.add_field(name=f'{PREFIX}clear [amount]', value='Delete 1-100 messages. Alias: delete.', inline=False)
        embed.add_field(name=f'{PREFIX}add_link <link>', value='Add a phishing link pattern that everyone can report for future auto-detection.', inline=False)
        embed.add_field(name=f'{PREFIX}reply <user_id> <message>', value='Reply to a user who opened a DM ticket.', inline=False)
        embed.add_field(name=f'{PREFIX}cases [member]', value='Show stored moderation cases.', inline=False)
        embed.add_field(name='Fun Commands', value=f'{PREFIX}trivia | {PREFIX}8ball <question> | {PREFIX}coinflip | {PREFIX}roll [sides] | {PREFIX}rps <rock/paper/scissors>', inline=False)
        embed.add_field(name=f'{PREFIX}lastphish', value='Show the most recent malicious-link log entry.', inline=False)
        embed.add_field(name=f'{PREFIX}ticketpanel', value='Post the ticket panel with a Create Ticket button (staff only).', inline=False)
        embed.add_field(name='Ticket Buttons', value='Staff can use Open Ticket and Close Ticket buttons inside each ticket channel.', inline=False)
        await ctx.send(embed=embed)

    async def ticketpanel(self, ctx):
        if self.ticket_panel_view is None:
            self.ticket_panel_view = TicketPanelView(self)
            self.add_view(self.ticket_panel_view)

        panel_channel = self.get_channel(TICKET_CHANNEL_ID) if TICKET_CHANNEL_ID else ctx.channel
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
        if panel_channel.id != ctx.channel.id:
            await ctx.send(f'✅ Ticket panel posted in {panel_channel.mention}.')

    async def cmdhelp(self, ctx):
        await self.cmd_help(ctx)
      
    async def ping(self, ctx):
        await ctx.send('🏓 Pong!')

    async def ban(self, ctx, member: discord.Member, *, reason='No reason'):
        await ctx.guild.ban(member, reason=reason)
        self._add_case('ban', member, ctx.author, reason)
        await ctx.send(f'✅ {member} banned')

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
    
    async def trivia(self, ctx):
        questions = await self._fetch_trivia_questions(10)
        if not questions:
            return await ctx.send('⚠️ Trivia service is unavailable right now. Try again in a moment.')

        await ctx.send('🎮 Trivia game started! Reply with `A`, `B`, `C`, or `D` for each question. You have 20 seconds per question.')

        score = 0
        total = min(10, len(questions))
        labels = ['A', 'B', 'C', 'D']

        for index, q in enumerate(questions[:total], start=1):
            correct = html.unescape(q.get('correct_answer', ''))
            incorrect = [html.unescape(x) for x in q.get('incorrect_answers', [])]
            options = incorrect + [correct]
            random.shuffle(options)
            correct_index = options.index(correct)

            embed = discord.Embed(
                title=f'🧠 Trivia {index}/{total}',
                description=html.unescape(q.get('question', 'No question text provided.')),
                color=discord.Color.gold(),
                timestamp=datetime.utcnow()
            )
            for i, opt in enumerate(options):
                embed.add_field(name=labels[i], value=opt[:1024], inline=False)

            await ctx.send(embed=embed)

            def answer_check(msg: discord.Message):
                if msg.author != ctx.author or msg.channel != ctx.channel:
                    return False
                answer = msg.content.strip().upper()
                return answer in labels

            try:
                reply = await self.wait_for('message', timeout=20.0, check=answer_check)
                guess = reply.content.strip().upper()
            except asyncio.TimeoutError:
                await ctx.send(f'⏱️ Time is up! Correct answer: **{labels[correct_index]}** - {correct}')
                self._update_trivia_leaderboard(ctx.author, correct=False)
                lb = self._format_trivia_leaderboard(limit=5)
                await ctx.send(f'📊 Trivia Leaderboard (Top 5):\n{lb}')
                continue

            guess_index = labels.index(guess)
            if guess_index == correct_index:
                score += 1
                await ctx.send('✅ Correct!')
                self._update_trivia_leaderboard(ctx.author, correct=True)
            else:
                await ctx.send(f'❌ Incorrect. Correct answer: **{labels[correct_index]}** - {correct}')
                self._update_trivia_leaderboard(ctx.author, correct=False)

            lb = self._format_trivia_leaderboard(limit=5)
            await ctx.send(f'📊 Trivia Leaderboard (Top 5):\n{lb}')

        await ctx.send(f'🏁 Game over, {ctx.author.mention}! Final score: **{score}/{total}**')

    async def eightball(self, ctx, *, question: str):
        responses = [
            'It is certain.', 'Without a doubt.', 'You may rely on it.',
            'Yes definitely.', 'Signs point to yes.', 'Reply hazy, try again.',
            'Ask again later.', 'Cannot predict now.', 'Don’t count on it.',
            'My reply is no.', 'Very doubtful.'
        ]
        answer = random.choice(responses)
        embed = discord.Embed(title='🎱 Magic 8-Ball', color=discord.Color.purple(), timestamp=datetime.utcnow())
        embed.add_field(name='Question', value=question[:1024], inline=False)
        embed.add_field(name='Answer', value=answer, inline=False)
        await ctx.send(embed=embed)

    async def coinflip(self, ctx):
        result = random.choice(['Heads', 'Tails'])
        await ctx.send(f'🪙 {ctx.author.mention} flipped: **{result}**')

    async def roll(self, ctx, sides: int = 6):
        if sides < 2 or sides > 1000:
            return await ctx.send('⚠️ Pick a number of sides between 2 and 1000.')
        result = random.randint(1, sides)
        await ctx.send(f'🎲 {ctx.author.mention} rolled a **{result}** (1-{sides})')

    async def rps(self, ctx, *, choice: str):
        user_choice = choice.strip().lower()
        valid = ['rock', 'paper', 'scissors']
        if user_choice not in valid:
            return await ctx.send('⚠️ Use: rock, paper, or scissors.')

        bot_choice = random.choice(valid)
        if user_choice == bot_choice:
            result = 'It\'s a tie!'
        elif (user_choice == 'rock' and bot_choice == 'scissors') or \
             (user_choice == 'paper' and bot_choice == 'rock') or \
             (user_choice == 'scissors' and bot_choice == 'paper'):
            result = 'You win!'
        else:
            result = 'I win!'

        await ctx.send(f'✊✋✌️ You: **{user_choice}** | Me: **{bot_choice}** — {result}')
  
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
    if not TOKEN or TOKEN == 'PASTE_YOUR_BOT_TOKEN_HERE':
        log.error('Set TOKEN in bot.py before running the bot')
        return
    bot = Bot()
    bot.run(TOKEN)

if __name__ == '__main__':
    main()


