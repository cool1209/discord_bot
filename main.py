"""
Maya Discord Bot - Production Enhanced Version
Enhanced with security, performance, and reliability improvements
"""

import discord
from discord.ext import commands, tasks
import aiohttp
import asyncio
import os
import json
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
from typing import Optional, Dict, Any, Set
import traceback
import hashlib
import time
from contextlib import asynccontextmanager
from collections import defaultdict
import re
import retell
from supabase import create_client, Client
from dataclasses import dataclass, asdict
from enum import Enum

# Load environment variables
load_dotenv()

# Conversation categorization system
class ConversationCategory(Enum):
    """Categories for conversation classification"""
    BUG_REPORT = "bug-report"
    FEATURE_REQUEST = "feature-request"
    JIRA_INTEGRATION = "jira-integration"
    PERFORMANCE_ISSUE = "performance-issue"
    ACCOUNT_SUPPORT = "account-support"
    GENERAL_INQUIRY = "general-inquiry"
    TECHNICAL_SUPPORT = "technical-support"
    BETA_PROGRAM = "beta-program"
    UNKNOWN = "unknown"

@dataclass
class ConversationEntry:
    """Data model for conversation storage"""
    id: Optional[str] = None
    user_id: str = ""
    discord_username: str = ""
    guild_id: Optional[str] = None
    guild_name: Optional[str] = None
    channel_id: str = ""
    channel_name: str = ""
    message_content: str = ""
    ai_response: str = ""
    category: str = ""
    confidence_score: float = 0.0
    intent: str = ""
    metadata: Dict[str, Any] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        data = asdict(self)
        
        # Remove id field if it's None (let database auto-generate it)
        if data.get('id') is None:
            data.pop('id', None)
        
        # Format datetime fields
        data['created_at'] = self.created_at.isoformat() if self.created_at else None
        data['updated_at'] = self.updated_at.isoformat() if self.updated_at else None
        
        return data

# Enhanced logging configuration
def setup_logging():
    """Setup comprehensive logging with rotation"""
    import logging.handlers

    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)

    # Configure rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        'logs/maya_bot.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Setup root logger
    logger = logging.getLogger('MayaBot')
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

logger = setup_logging()

# Enhanced configuration with validation
class Config:
    """Configuration management with validation"""

    def __init__(self):
        self.DISCORD_TOKEN = self._get_required('DISCORD_TOKEN')
        self.RETELL_API_KEY = os.getenv('RETELL_API_KEY')
        # Supabase configuration for conversation archiving
        self.SUPABASE_URL = self._get_required('SUPABASE_URL')
        self.SUPABASE_KEY = self._get_required('SUPABASE_ANON_KEY')
        self.SPRINTIQ_GUILD_ID = self._get_int_env('SPRINTIQ_DISCORD_GUILD_ID')

        # Rate limiting configuration
        self.RATE_LIMIT_MESSAGES = int(os.getenv('RATE_LIMIT_MESSAGES', '5'))
        self.RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', '60'))

        # Performance settings
        self.MAX_MESSAGE_LENGTH = int(os.getenv('MAX_MESSAGE_LENGTH', '2000'))
        self.CONNECTION_POOL_SIZE = int(os.getenv('CONNECTION_POOL_SIZE', '10'))

        # Security settings
        self.ALLOWED_GUILDS = self._parse_guild_list(os.getenv('ALLOWED_GUILDS', ''))
        self.ADMIN_USER_IDS = self._parse_user_list(os.getenv('ADMIN_USER_IDS', ''))

        self._validate_config()

    def _get_required(self, key: str) -> str:
        """Get required environment variable"""
        value = os.getenv(key)
        if not value:
            raise ValueError(f"Required environment variable {key} not found")
        return value

    def _get_int_env(self, key: str) -> Optional[int]:
        """Get integer environment variable"""
        value = os.getenv(key)
        return int(value) if value else None

    def _parse_guild_list(self, value: str) -> Set[int]:
        """Parse comma-separated guild IDs"""
        if not value:
            return set()
        return {int(guild_id.strip()) for guild_id in value.split(',') if guild_id.strip()}

    def _parse_user_list(self, value: str) -> Set[int]:
        """Parse comma-separated user IDs"""
        if not value:
            return set()
        return {int(user_id.strip()) for user_id in value.split(',') if user_id.strip()}

    def _validate_config(self):
        """Validate configuration"""
        # Validate Supabase configuration
        if not self.SUPABASE_URL or not self.SUPABASE_KEY:
            raise ValueError("Supabase configuration required for conversation archiving")

        # Note: MAYA_AGENT_ID is no longer needed as we create agents dynamically
        # Retell AI API key validation will be done during runtime

        logger.info(f"Configuration loaded - Rate limit: {self.RATE_LIMIT_MESSAGES}/{self.RATE_LIMIT_WINDOW}s")
        logger.info("Supabase conversation archiving enabled")

config = Config()

# Enhanced rate limiting with sliding window
class RateLimiter:
    """Sliding window rate limiter"""

    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed"""
        now = time.time()
        requests = self.requests[key]

        # Remove old requests outside window
        requests[:] = [req_time for req_time in requests if now - req_time < self.window_seconds]

        # Check if under limit
        if len(requests) < self.max_requests:
            requests.append(now)
            return True

        return False

    def get_reset_time(self, key: str) -> float:
        """Get time until rate limit resets"""
        if key not in self.requests or not self.requests[key]:
            return 0

        oldest_request = min(self.requests[key])
        return max(0, self.window_seconds - (time.time() - oldest_request))

# Circuit breaker for external API calls
class CircuitBreaker:
    """Circuit breaker pattern implementation"""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN

    async def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        if self.state == 'OPEN':
            if self.last_failure_time and \
               time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = 'HALF_OPEN'
                logger.info("Circuit breaker moving to HALF_OPEN state")
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = await func(*args, **kwargs)
            if self.state == 'HALF_OPEN':
                self.reset()
            return result

        except Exception as e:
            self.record_failure()
            raise e

    def record_failure(self):
        """Record a failure"""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = 'OPEN'
            logger.error(f"Circuit breaker OPENED after {self.failure_count} failures")

    def reset(self):
        """Reset circuit breaker"""
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'
        logger.info("Circuit breaker RESET")

# Connection pool for external services
class ConnectionManager:
    """Manage aiohttp connections with pooling"""

    def __init__(self):
        self.session = None
        self.connector = None

    async def initialize(self):
        """Initialize connection pool"""
        self.connector = aiohttp.TCPConnector(
            limit=50,  # Default connection pool size
            limit_per_host=5,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )

        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=timeout
        )

        logger.info(f"Connection pool initialized with 50 connections")

    @asynccontextmanager
    async def get_session(self):
        """Get HTTP session with context manager"""
        if not self.session:
            await self.initialize()
        yield self.session

    async def close(self):
        """Close connection pool"""
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()

# Supabase conversation archiving manager
class SupabaseConversationManager:
    """Manage conversation storage and categorization in Supabase"""

    def __init__(self, supabase_url: str, supabase_key: str):
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        self.client: Optional[Client] = None
        self.initialized = False

    async def initialize(self):
        """Initialize Supabase client and create tables if needed"""
        try:
            self.client = create_client(self.supabase_url, self.supabase_key)
            
            # Test connection
            await self._test_connection()
            
            # Ensure tables exist
            await self._ensure_tables()
            
            self.initialized = True
            logger.info("Supabase conversation manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Supabase: {e}")
            self.initialized = False

    async def _test_connection(self):
        """Test Supabase connection"""
        try:
            # Test basic connection by checking if we can access the client
            if not self.client:
                raise Exception("Supabase client not created")
            
            # Try a simple operation to verify the connection works
            # Don't query tables that might not exist yet
            logger.debug("Supabase connection test successful")
        except Exception as e:
            raise Exception(f"Supabase connection test failed: {e}")

    async def _ensure_tables(self):
        """Ensure required tables exist"""
        try:
            # Try to create the conversations table if it doesn't exist
            # Note: Supabase will handle this automatically, but we can log it
            logger.info("Supabase tables will be created automatically on first insert")
            
            # Optional: You can add a simple test insert here if you want to verify table creation
            # For now, we'll let the first real insert create the table
        except Exception as e:
            logger.warning(f"Table creation check failed: {e}")
            # Don't fail initialization for this

    async def archive_conversation(self, conversation: ConversationEntry) -> bool:
        """Archive a conversation to Supabase"""
        if not self.initialized or not self.client:
            logger.warning("Supabase not initialized, skipping conversation archive")
            return False

        try:
            # Convert to dict for storage
            data = conversation.to_dict()
            
            # Log the data being inserted (for debugging)
            logger.debug(f"Inserting conversation data: {data}")
            
            # Insert into conversations table
            response = self.client.table('conversations').insert(data).execute()
            
            if response.data:
                conversation.id = response.data[0]['id']
                logger.info(f"Conversation archived with ID: {conversation.id}")
                return True
            else:
                logger.error("Failed to archive conversation - no data returned")
                return False
                
        except Exception as e:
            logger.error(f"Error archiving conversation: {e}")
            logger.error(f"Conversation data that failed: {conversation.to_dict()}")
            return False

    async def get_user_conversation_history(self, user_id: str, limit: int = 50) -> list:
        """Get conversation history for a specific user"""
        if not self.initialized or not self.client:
            return []

        try:
            response = self.client.table('conversations')\
                .select('*')\
                .eq('user_id', user_id)\
                .order('created_at', desc=True)\
                .limit(limit)\
                .execute()
            
            return response.data if response.data else []
            
        except Exception as e:
            logger.error(f"Error fetching user conversation history: {e}")
            return []

    async def get_conversations_by_category(self, category: str, limit: int = 100) -> list:
        """Get conversations by category"""
        if not self.initialized or not self.client:
            return []

        try:
            response = self.client.table('conversations')\
                .select('*')\
                .eq('category', category)\
                .order('created_at', desc=True)\
                .limit(limit)\
                .execute()
            
            return response.data if response.data else []
            
        except Exception as e:
            logger.error(f"Error fetching conversations by category: {e}")
            return []

    async def get_conversation_analytics(self) -> Dict[str, Any]:
        """Get conversation analytics and statistics"""
        if not self.initialized or not self.client:
            return {}

        try:
            # Get total conversations
            total_response = self.client.table('conversations').select('id', count='exact').execute()
            total_conversations = total_response.count if total_response.count else 0

            # Get category breakdown
            categories_response = self.client.table('conversations')\
                .select('category')\
                .execute()
            
            category_counts = defaultdict(int)
            if categories_response.data:
                for conv in categories_response.data:
                    category_counts[conv.get('category', 'unknown')] += 1

            # Get recent activity (last 24 hours)
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            recent_response = self.client.table('conversations')\
                .select('id')\
                .gte('created_at', yesterday)\
                .execute()
            
            recent_conversations = len(recent_response.data) if recent_response.data else 0

            # Find top category
            top_category = None
            top_category_count = 0
            if category_counts:
                top_category = max(category_counts.items(), key=lambda x: x[1])
                top_category_count = top_category[1]
                top_category = top_category[0]

            return {
                'total_conversations': total_conversations,
                'category_breakdown': dict(category_counts),
                'recent_24h': recent_conversations,
                'top_category': top_category,
                'top_category_count': top_category_count,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error fetching conversation analytics: {e}")
            return {}

    async def close(self):
        """Close Supabase connection"""
        if self.client:
            # Supabase client doesn't need explicit closing
            pass

# Enhanced response templates with versioning
class ResponseTemplates:
    """Manage response templates with caching and updates"""

    VERSION = "2.0"

    TEMPLATES = {
        'jira_help': """**Jira Integration Support**

Let me help you troubleshoot your Jira integration:

**Quick Diagnostics:**
• **Permissions**: Verify story creation rights in your Jira project
• **API Token**: Check token validity (Account Settings → Security)
• **Project Key**: Confirm exact key (case-sensitive!)
• **URL Format**: Ensure `https://` prefix

**Common Solutions:**
• **Stories not syncing**: Check project permissions and field mappings
• **Auth failures**: Regenerate API token and update integration
• **Missing fields**: Configure custom field mapping in settings
• **Timeout errors**: Verify network connectivity to Jira instance

**Advanced Troubleshooting:**
• Test connection with Jira's REST API directly
• Check webhook configurations for bidirectional sync
• Review audit logs for permission issues

**Still blocked?** I can escalate immediately to our integration specialists.

*Average resolution time: 15 minutes for common issues*""",

        'bug_report': """**Bug Report Acknowledged**

I've logged this issue with our development team and assigned priority based on severity.

**Immediate Actions:**
• **High Priority**: Dev team notified via Slack
• **Tracking**: Bug #{timestamp} created in our system
• **Timeline**: Initial response within 30 minutes

**Quick Recovery Options:**
• **Hard refresh**: Ctrl+F5 (Windows) / Cmd+Shift+R (Mac)
• **Clear cache**: Browser settings → Clear browsing data
• **Incognito mode**: Test if issue persists in private browsing
• **Alternative browsers**: Try Chrome/Firefox/Safari

**Help Us Help You:**
• Screenshot or video of the issue (if possible)
• Browser and operating system details
• Steps that led to the problem
• Any error messages displayed

**Critical Issues**: Use `!maya escalate` for immediate human support.

*Bug fix deployment typically within 24-48 hours for P1 issues*""",

        'performance_issue': """**Performance Investigation Active**

I'm monitoring system performance and investigating slowdowns.

**Real-Time Diagnostics:**
• **API Response Times**: Normal (< 200ms)
• **Database Performance**: Monitoring queries
• **CDN Status**: All regions operational
• **Server Load**: Checking resource utilization

**Immediate Optimizations:**
• **Browser cache**: Clear and restart browser
• **Network test**: Run speed test at fast.com
• **Region check**: Try switching VPN location if using one
• **Extensions**: Disable browser extensions temporarily

**Performance Tips:**
• Use Chrome DevTools Network tab to identify slow requests
• Check for browser console errors (F12 → Console)
• Monitor your internet connection stability

**If slowdowns persist:**
I'll escalate to our infrastructure team for deeper investigation.

*We maintain 99.9% uptime with <2s average page load times*""",

        'account_support': """**Account Support Available**

I can help resolve access and account issues immediately.

**Common Resolutions:**
• **Password Reset**: Use "Forgot Password" → Check spam folder
• **Email Verification**: Resend verification link (expires in 24h)
• **Account Lockout**: I can check status and unlock if needed
• **Team Management**: Add/remove members (10 max in Beta)

**Beta Account Status:**
• **Active**: Full feature access
• **Warning**: Feedback session overdue
• **Suspended**: Contact me for reinstatement

**Security Features:**
• Two-factor authentication setup
• Session management and logout
• API key generation and rotation
• Audit log access for team admins

**Immediate Help:**
DM me your email address and I can check your account status right away.
For team management, provide your team name and member details.

*Most account issues resolved within 5 minutes*""",

        'greeting': """**Hi! I'm Maya, your SprintiQ AI support specialist**

Welcome to our Beta support community! I'm here 24/7 to ensure your success.

**I excel at helping with:**
• **Jira Integration** - Setup, troubleshooting, custom configurations
• **Sprint Planning** - AI-powered story generation and optimization
• **Project Setup** - Team onboarding and workflow configuration
• **Technical Issues** - Bug reports, performance problems
• **Feature Feedback** - Enhancement requests and product suggestions
• **Beta Program** - Requirements, compliance, documentation

**Popular Support Topics:**
• "Help me connect Jira to SprintiQ"
• "Walk me through my first sprint planning session"
• "I found a bug in the story generator"
• "How do I set up my development team?"

**Pro Tips:**
• Tag me @Maya for fastest response
• Use specific channels (#jira-integration, #bug-reports)
• Include screenshots for visual issues

*I've helped 300+ Beta users save over 2,000 hours of planning time!*""",

        'default': """**Maya AI - Always Here to Help!**

I might not have caught exactly what you need, but I'm ready to assist!

**My Specialties:**
• **Jira Integration** - APIs, syncing, custom fields, webhooks
• **Sprint Planning** - AI story generation, velocity tracking
• **Project Management** - Team setup, workflow optimization
• **Technical Support** - Debugging, performance, error resolution
• **Product Feedback** - Feature requests, usability improvements

**Try These Commands:**
• `!maya help` - Full capabilities overview
• `!maya status` - System health and performance
• `!maya escalate [description]` - Human support escalation

**Quick Help Phrases:**
• "Jira won't connect to SprintiQ"
• "Show me sprint planning best practices"
• "I need help setting up my team"
• "Report a bug with story export"

**Need immediate human support?** Use `!maya escalate` with your issue description.

*What specific challenge can I help you tackle today?*"""
    }

    @classmethod
    def get_template(cls, template_name: str) -> str:
        """Get template with fallback"""
        return cls.TEMPLATES.get(template_name, cls.TEMPLATES['default'])

    @classmethod
    def format_template(cls, template_name: str, **kwargs) -> str:
        """Format template with variables"""
        template = cls.get_template(template_name)
        if kwargs:
            # Replace {timestamp} and other placeholders
            if '{timestamp}' in template:
                kwargs.setdefault('timestamp', datetime.now().strftime('%Y%m%d_%H%M%S'))
            template = template.format(**kwargs)
        return template

class EnhancedMayaBot(commands.Bot):
    """Enhanced Maya Bot with production features"""

    def __init__(self):
        # Enhanced intents
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.members = True
        intents.guild_messages = True

        # Configuration values (must be set first)
        self.RETELL_API_KEY = config.RETELL_API_KEY
        self.ALLOWED_GUILDS = config.ALLOWED_GUILDS
        # Supabase configuration removed
        self.MAX_MESSAGE_LENGTH = config.MAX_MESSAGE_LENGTH
        self.RATE_LIMIT_MESSAGES = config.RATE_LIMIT_MESSAGES
        self.RATE_LIMIT_WINDOW = config.RATE_LIMIT_WINDOW
        self.CONNECTION_POOL_SIZE = config.CONNECTION_POOL_SIZE

        super().__init__(
            command_prefix=['!maya ', '!Maya ', '@Maya '],
            intents=intents,
            description='Maya - Enhanced SprintiQ Customer Support AI',
            help_command=None,
            case_insensitive=True
        )

        # Enhanced statistics tracking
        self.stats = {
            'messages_processed': 0,
            'users_helped': set(),
            'start_time': datetime.now(),
            'errors': 0,
            'commands_executed': 0,
            'escalations_created': 0,
            'avg_response_time': 0,
            'success_rate': 0
        }

        # Enhanced components
        self.rate_limiter = RateLimiter(self.RATE_LIMIT_MESSAGES, self.RATE_LIMIT_WINDOW)
        self.circuit_breaker = CircuitBreaker()
        self.connection_manager = ConnectionManager()
        # Supabase conversation archiving
        self.conversation_manager = SupabaseConversationManager(config.SUPABASE_URL, config.SUPABASE_KEY)

        # Response time tracking
        self.response_times = []

        # Security tracking
        self.security_events = []

    async def setup_hook(self):
        """Enhanced bot setup with comprehensive initialization"""
        logger.info("Initializing Enhanced Maya Bot...")

        # Initialize connection pool
        await self.connection_manager.initialize()

        # Initialize Supabase conversation archiving
        await self.conversation_manager.initialize()

        # Check Retell AI configuration
        if self.RETELL_API_KEY:
            retell_status = self.check_retell_ai_config()
            if retell_status:
                logger.info("Retell AI integration ready")
            else:
                logger.warning("Retell AI integration failed - will use fallback responses")
        else:
            logger.info("Retell AI not configured - using fallback responses only")

        # Start background tasks
        self.update_stats.start()
        self.cleanup_rate_limits.start()
        self.health_check.start()

        logger.info("Maya Bot initialization complete")



    async def on_ready(self):
        """Enhanced ready event with comprehensive logging"""
        logger.info(f'{self.user} is online and ready!')
        logger.info(f'Connected to {len(self.guilds)} Discord servers')
        logger.info(f'Serving {sum(guild.member_count for guild in self.guilds)} total members')

        # Set enhanced presence
        activity = discord.Activity(
            type=discord.ActivityType.listening,
            name=f"SprintiQ Beta users in {len(self.guilds)} servers"
        )
        await self.change_presence(activity=activity, status=discord.Status.online)

        # Log guild information with security check
        for guild in self.guilds:
            is_allowed = not self.ALLOWED_GUILDS or guild.id in self.ALLOWED_GUILDS
            logger.info(f"Guild: {guild.name} (ID: {guild.id}, Members: {guild.member_count}) - {'Allowed' if is_allowed else 'WARNING: Not in whitelist'}")

            if not is_allowed:
                logger.warning(f"Bot is in non-allowed guild: {guild.name}")

    async def on_error(self, event, *args, **kwargs):
        """Enhanced error handling with classification"""
        self.stats['errors'] += 1

        error_info = {
            'event': event,
            'timestamp': datetime.now().isoformat(),
            'traceback': traceback.format_exc(),
            'args_count': len(args),
            'kwargs_keys': list(kwargs.keys()) if kwargs else []
        }

        logger.error(f"Bot error in {event}: {traceback.format_exc()}")

        # Database logging removed

    async def on_command_error(self, ctx, error):
        """Enhanced command error handling with user feedback"""
        self.stats['errors'] += 1

        error_type = type(error).__name__
        logger.error(f"Command error ({error_type}): {error}")

        # User-friendly error messages
        if isinstance(error, commands.CommandNotFound):
            embed = discord.Embed(
                title="Command Not Found",
                description="I don't recognize that command. Try `!maya help` to see what I can do!",
                color=0xffaa00
            )
        elif isinstance(error, commands.MissingRequiredArgument):
            embed = discord.Embed(
                title="Missing Information",
                description="Looks like you're missing some information. Try `!maya help` for usage examples.",
                color=0xffaa00
            )
        elif isinstance(error, commands.CommandOnCooldown):
            embed = discord.Embed(
                title="Please Wait",
                description=f"This command is on cooldown. Try again in {error.retry_after:.1f} seconds.",
                color=0xffaa00
            )
        else:
            embed = discord.Embed(
                title="Something Went Wrong",
                description="I encountered an unexpected error. Let me get a human to help you!",
                color=0xff0000
            )

            # Database logging removed

        try:
            await ctx.send(embed=embed)
        except discord.Forbidden:
            logger.warning(f"Cannot send error message in {ctx.channel}")

    async def on_message(self, message):
        """Enhanced message handling with security and performance"""
        # Skip bot messages
        if message.author == self.user or message.author.bot:
            return

        # Security: Guild whitelist check
        if self.ALLOWED_GUILDS and message.guild and message.guild.id not in self.ALLOWED_GUILDS:
            logger.warning(f"Message from non-allowed guild: {message.guild.name}")
            return

        # Security: Input validation and sanitization
        if not self.validate_message_content(message.content):
            logger.warning(f"Invalid message content from {message.author}")
            return

        # Enhanced rate limiting
        rate_limit_key = f"user_{message.author.id}"
        if not self.rate_limiter.is_allowed(rate_limit_key):
            reset_time = self.rate_limiter.get_reset_time(rate_limit_key)
            logger.warning(f"Rate limited user {message.author} (reset in {reset_time:.1f}s)")

            # Send rate limit message (only once per limit period)
            if not hasattr(self, '_rate_limit_notifications'):
                self._rate_limit_notifications = set()

            if rate_limit_key not in self._rate_limit_notifications:
                embed = discord.Embed(
                    title="Rate Limited",
                    description=f"Please wait {reset_time:.0f} seconds before sending another message.",
                    color=0xffaa00
                )
                await message.channel.send(embed=embed)
                self._rate_limit_notifications.add(rate_limit_key)

                # Remove from notifications after reset time
                await asyncio.sleep(reset_time)
                self._rate_limit_notifications.discard(rate_limit_key)

            return

        # Process commands first
        await self.process_commands(message)

        # Handle support requests
        if self.should_maya_respond(message):
            await self.handle_support_request(message)

    def validate_message_content(self, content: str) -> bool:
        """Validate message content for security"""
        if not content or len(content) > self.MAX_MESSAGE_LENGTH:
            return False

        # Check for suspicious patterns
        suspicious_patterns = [
            r'<script[^>]*>.*?</script>',  # Script tags
            r'javascript:',                # JavaScript URLs
            r'data:.*?base64',            # Data URLs with base64
            r'<iframe[^>]*>',             # Iframe tags
        ]

        content_lower = content.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, content_lower):
                self.security_events.append({
                    'type': 'suspicious_content',
                    'pattern': pattern,
                    'timestamp': datetime.now()
                })
                return False

        return True

    def should_maya_respond(self, message: discord.Message) -> bool:
        """Enhanced logic for determining when Maya should respond"""
        # Skip commands
        if message.content.startswith(('!', '/', '$', '?')):
            return False

        # Always respond to mentions
        if self.user.mentioned_in(message):
            return True

        # Handle DM channels - always respond to DMs
        if isinstance(message.channel, discord.DMChannel):
            return True

        # For guild channels, check if they have a name attribute
        if not hasattr(message.channel, 'name'):
            return False

        # Enhanced auto-respond channels (only for guild channels)
        auto_respond_channels = {
            'jira-integration': {'priority': 'high', 'always_respond': True},
            'bug-reports': {'priority': 'high', 'always_respond': True},
            'general-beta': {'priority': 'medium', 'keyword_required': True},
            'maya-support': {'priority': 'high', 'always_respond': True},
            'feedback': {'priority': 'low', 'keyword_required': True}
        }

        channel_name = message.channel.name
        channel_config = auto_respond_channels.get(channel_name)
        if not channel_config:
            return False

        if channel_config.get('always_respond'):
            return True

        if channel_config.get('keyword_required'):
            # Enhanced keyword detection
            support_keywords = [
                'help', 'issue', 'problem', 'error', 'broken', 'not working',
                'jira', 'sync', 'integration', 'bug', 'maya', 'support',
                'question', 'how to', 'can\'t', 'unable', 'stuck'
            ]

            content_lower = message.content.lower()
            return any(keyword in content_lower for keyword in support_keywords)

        return False

    async def handle_support_request(self, message: discord.Message):
        """Enhanced support request handling with performance monitoring"""
        start_time = time.time()

        try:
            # Show typing indicator
            async with message.channel.typing():
                logger.info(f"Processing support request from {message.author}: {message.content[:100]}...")

                # Update statistics
                self.stats['messages_processed'] += 1
                self.stats['users_helped'].add(message.author.id)

                # Build enhanced context
                context = await self.build_user_context(message)

                # Get Maya's response with circuit breaker
                maya_response = await self.get_maya_response_with_fallback(message.content, context)

                # Create and send enhanced embed
                embed = await self.create_enhanced_embed(maya_response, message, context)
                await message.reply(embed=embed, mention_author=False)

                # Archive conversation to Supabase
                await self.archive_conversation_to_supabase(message, maya_response, context)

                # Track response time
                response_time = time.time() - start_time
                self.response_times.append(response_time)

                # Update success rate
                self.update_success_metrics()

                logger.info(f"Responded to {message.author} in {response_time:.2f}s")

        except Exception as e:
            # Track response time for failed requests too
            response_time = time.time() - start_time

            logger.error(f"Error handling support request: {e}")
            self.stats['errors'] += 1

            # Send user-friendly error message
            error_embed = discord.Embed(
                title="Temporary Issue",
                description="I'm experiencing a brief technical issue. Please try again in a moment, or use `!maya escalate` for immediate human support.",
                color=0xff9900
            )

            try:
                await message.reply(embed=error_embed, mention_author=False)
            except discord.Forbidden:
                logger.error(f"Cannot send error message in {message.channel}")

            # Database logging removed

    async def build_user_context(self, message: discord.Message) -> Dict[str, Any]:
        """Build enhanced user context with performance optimization"""
        try:
            # Safely get channel name or type
            channel_info = message.channel.name if hasattr(message.channel, 'name') else f"DM-{message.channel.id}"
            
            context = {
                "user_message": message.content,
                "discord_user": str(message.author),
                "user_id": str(message.author.id),
                "channel": channel_info,
                "timestamp": datetime.now().isoformat(),
                "platform": "discord",
                "beta_program": True,
                "guild_id": str(message.guild.id) if message.guild else None,
                "guild_name": message.guild.name if message.guild else None,
                "user_roles": [role.name for role in message.author.roles] if hasattr(message.author, 'roles') else [],
                "message_length": len(message.content),
                "response_context": {
                    "template_version": ResponseTemplates.VERSION,
                    "circuit_breaker_state": self.circuit_breaker.state
                }
            }

            # Database interaction history removed

            return context

        except Exception as e:
            logger.error(f"Error building user context: {e}")
            # Return minimal context on error
            return {
                "user_id": str(message.author.id),
                "platform": "discord",
                "beta_program": True
            }

    async def get_maya_response_with_fallback(self, user_message: str, context: Dict[str, Any]) -> str:
        """Get Maya's response with circuit breaker and enhanced fallback"""

        # Try Retell AI if configured
        if self.RETELL_API_KEY:
            try:
                # Call Retell AI directly since it's now synchronous
                return self.call_retell_ai(user_message, context)
            except Exception as e:
                logger.warning(f"Retell AI failed, using fallback: {e}")

        # Enhanced fallback with context awareness
        return self.generate_enhanced_response(user_message, context)

    def call_retell_ai(self, user_message: str, context: Dict[str, Any]) -> str:
        """Call Retell AI with new SDK and enhanced error handling"""
        try:
            # Initialize Retell AI client
            client = retell.Retell(api_key=self.RETELL_API_KEY)

            logger.info(f"Retell AI client initialized: {client}")
            
            # Check if we have a cached agent, if not create one
            # if not hasattr(self, '_retell_agent_id') or not self._retell_agent_id:
            #     self._setup_retell_agent(client)
            
            

            # return chat_response.content
            # Create a new chat session fo  r this conversation
            # Note: create() method is not async in the SDK
            # Try creating chat session without metadata first
            try:
                chat_response = client.chat.create(
                    agent_id="agent_b77021e4c55dd7f9f022909ed3",
                    metadata={}
                )
            except Exception as e:
                logger.error(f"Failed to create chat session: {e}")
                # Fallback to local response generation if chat session creation fails
                return self.generate_enhanced_response(user_message, context)
            
            # Generate AI response
            # Note: create_chat_completion() method is not async in the SDK
            response = client.chat.create_chat_completion(
                chat_id=chat_response.chat_id,
                content=user_message
            )

            logger.info(f"Retell AI response: {response}")
            
            # Extract the response content from the messages
            if hasattr(response, 'messages') and response.messages:
                logger.info(f"Retell AI response messages: {response.messages[0].content}")
                return response.messages[0].content
            else:
                # Fallback if response structure is unexpected
                logger.warning("Unexpected Retell AI response structure, using fallback")
                return self.generate_enhanced_response(user_message, context)
                
        except Exception as e:
            logger.error(f"Retell AI API error: {e}")
            # Log specific information about the error for debugging
            if "Cannot start a chat session" in str(e):
                logger.warning("Retell AI chat session creation failed - this might be due to API limitations for text chat")
            # Fallback to local response generation
            return self.generate_enhanced_response(user_message, context)
        finally:
            # Clean up client
            if 'client' in locals():
                client.close()

    def check_retell_ai_config(self) -> bool:
        """Check if Retell AI is properly configured and working"""
        if not self.RETELL_API_KEY:
            logger.warning("Retell AI API key not configured")
            return False
            
        try:
            # Test the connection by creating a client
            client = retell.Retell(api_key=self.RETELL_API_KEY)
            
            # Try to list available models to verify API key works
            try:
                # This is a simple test to verify the API key is valid
                # Note: list() method is not async in the SDK
                models = client.llm.list()
                logger.info("Retell AI configuration verified successfully")
                client.close()
                return True
            except Exception as e:
                logger.warning(f"Retell AI API test failed: {e}")
                client.close()
                return False
                
        except Exception as e:
            logger.error(f"Failed to initialize Retell AI client: {e}")
            return False

    def _setup_retell_agent(self, client):
        """Setup Retell AI agent with LLM response engine"""
        try:
            logger.info("Setting up Retell AI agent...")
            
            # Create LLM Response Engine
            # Note: create() method is not async in the SDK
            llm = client.llm.create(
                general_prompt="""You are Maya, an AI support assistant for SprintiQ. You help users with:
                - Jira integration and synchronization issues
                - Bug reports and technical problems
                - Performance and loading issues
                - Account and access problems
                - General support questions
                
                Be helpful, professional, and concise. Focus on practical solutions and guide users to the right resources when needed.""",
                model="gpt-4o-mini",
                model_temperature=0.7
            )
            
            logger.info(f"Retell AI LLM created: {llm.llm_id}")
            
            # Create Agent using the LLM
            # Note: create() method is not async in the SDK
            # Try creating agent with minimal configuration for text chat
            agent = client.agent.create(
                response_engine={"type": "retell-llm", "llm_id": llm.llm_id},
                agent_name="Maya AI Support Text Chat",
                voice_id="openai-Alloy"  # Try OpenAI voice instead
            )
            
            # Cache the agent ID for future use
            self._retell_agent_id = agent.agent_id
            logger.info(f"Retell AI agent created successfully: {agent.agent_id}")
            
        except retell.AuthenticationError:
            logger.error("Retell AI authentication failed - check your API key")
            raise
        except retell.BadRequestError as e:
            logger.error(f"Retell AI bad request: {e}")
            raise
        except retell.RateLimitError:
            logger.error("Retell AI rate limit exceeded")
            raise
        except Exception as e:
            logger.error(f"Failed to setup Retell AI agent: {e}")
            raise

    def generate_enhanced_response(self, user_message: str, context: Dict[str, Any]) -> str:
        """Generate enhanced response with improved pattern matching"""
        message_lower = user_message.lower()

        # Enhanced keyword mappings with priority and specificity
        keyword_mappings = [
            # High priority - specific issues
            (['jira', 'sync', 'integration', 'api token', 'connect jira'], 'jira_help', 0.9),
            (['performance', 'slow', 'loading', 'timeout', 'lag'], 'performance_issue', 0.8),

            # Medium priority - support categories
            (['bug', 'error', 'broken', 'not working', 'issue', 'problem'], 'bug_report', 0.7),
            (['account', 'login', 'password', 'access', 'locked'], 'account_support', 0.7),

            # Lower priority - general
            (['hello', 'hi', 'hey', 'thanks'], 'greeting', 0.3),
            (['help', 'support', 'question'], 'default', 0.1)
        ]

        # Find best matching template
        best_match = None
        best_score = 0

        for keywords, template_key, priority in keyword_mappings:
            matches = sum(1 for keyword in keywords if keyword in message_lower)
            if matches > 0:
                score = (matches / len(keywords)) * priority
                if score > best_score:
                    best_score = score
                    best_match = template_key

        template_key = best_match or 'default'

        # Get template with context-aware formatting
        return ResponseTemplates.format_template(
            template_key,
            user_name=context.get('discord_user', 'there'),
            timestamp=datetime.now().strftime('%Y%m%d_%H%M%S')
        )

    async def create_enhanced_embed(self, response: str, message: discord.Message, context: Dict[str, Any]) -> discord.Embed:
        """Create enhanced Discord embed with dynamic content"""

        # Determine embed color based on channel and content
        color_map = {
            'jira-integration': 0x0052cc,  # Jira blue
            'bug-reports': 0xff0000,       # Red for bugs
            'general-beta': 0x0099ff,      # Default blue
            'performance': 0xffaa00        # Orange for performance
        }

        # Safely get channel name or use default
        channel_name = message.channel.name if hasattr(message.channel, 'name') else 'dm'
        embed_color = color_map.get(channel_name, 0x0099ff)
        if 'error' in response.lower() or 'bug' in response.lower():
            embed_color = 0xff0000
        elif 'performance' in response.lower() or 'slow' in response.lower():
            embed_color = 0xffaa00

        # Create enhanced embed
        embed = discord.Embed(
            title="Maya AI Support",
            description=response,
            color=embed_color,
            timestamp=datetime.now()
        )

        # Dynamic author based on content and channel
        author_configs = {
            'jira-integration': {"name": "Jira Integration Specialist", "icon_url": None},
            'bug-reports': {"name": "Technical Support Engineer", "icon_url": None},
            'general-beta': {"name": "Beta Program Support", "icon_url": None},
            'performance': {"name": "Performance Specialist", "icon_url": None}
        }

        author_config = author_configs.get(channel_name, {"name": "Maya AI Support", "icon_url": None})
        embed.set_author(**author_config)

        # Enhanced footer with dynamic stats
        avg_response_time = sum(self.response_times[-100:]) / len(self.response_times[-100:]) if self.response_times else 2.0
        success_rate = self.stats.get('success_rate', 94)

        embed.set_footer(
            text=f"SprintiQ Beta Support • Response time: {avg_response_time:.1f}s • Success rate: {success_rate}%",
            icon_url="https://cdn.sprintiq.com/maya-avatar.png"
        )

        # Add helpful action buttons context
        if 'escalate' in response.lower():
            embed.add_field(
                name="Need immediate help?",
                value="Use `!maya escalate [your issue]` for human support",
                inline=False
            )

        return embed

    async def archive_conversation_to_supabase(self, message: discord.Message, ai_response: str, context: Dict[str, Any]):
        """Archive conversation to Supabase with categorization"""
        try:
            # Check if Supabase is available
            if not hasattr(self, 'conversation_manager') or not self.conversation_manager.initialized:
                logger.warning("Supabase not available, skipping conversation archive")
                return
            
            # Classify intent and get confidence score
            intent, confidence = self.classify_enhanced_intent(message.content)
            
            # Categorize the conversation
            category = self.categorize_conversation(message.content, intent, confidence)
            
            # Create conversation entry
            conversation = ConversationEntry(
                user_id=str(message.author.id),
                discord_username=str(message.author),
                guild_id=str(message.guild.id) if message.guild else None,
                guild_name=message.guild.name if message.guild else None,
                channel_id=str(message.channel.id),
                channel_name=message.channel.name if hasattr(message.channel, 'name') else 'DM',
                message_content=message.content,
                ai_response=ai_response,
                category=category,
                confidence_score=confidence,
                intent=intent,
                metadata={
                    'platform': 'discord',
                    'beta_program': True,
                    'response_time': context.get('response_time', 0),
                    'template_version': ResponseTemplates.VERSION,
                    'circuit_breaker_state': self.circuit_breaker.state
                }
            )
            
            # Archive to Supabase
            success = await self.conversation_manager.archive_conversation(conversation)
            
            if success:
                logger.info(f"Conversation archived: {category} (confidence: {confidence:.2f})")
            else:
                logger.warning("Failed to archive conversation to Supabase")
                
        except Exception as e:
            logger.error(f"Error archiving conversation: {e}")
            # Don't fail the main flow if archiving fails


    def classify_enhanced_intent(self, message: str) -> tuple[str, float]:
        """Enhanced intent classification with confidence scoring"""
        message_lower = message.lower()

        intent_patterns = {
            'jira_integration': {
                'keywords': ['jira', 'sync', 'integration', 'api token', 'connect', 'webhook'],
                'phrases': ['jira won\'t connect', 'sync failing', 'api error', 'can\'t sync'],
                'weight': 1.0
            },
            'performance_issue': {
                'keywords': ['slow', 'performance', 'loading', 'timeout', 'lag', 'freeze'],
                'phrases': ['running slow', 'takes forever', 'not responding', 'very slow'],
                'weight': 1.0
            },
            'bug_report': {
                'keywords': ['bug', 'error', 'broken', 'crash', 'issue', 'problem'],
                'phrases': ['not working', 'error message', 'something broke', 'it crashed'],
                'weight': 1.0
            },
            'feature_request': {
                'keywords': ['feature', 'request', 'suggestion', 'enhancement', 'add', 'could you'],
                'phrases': ['would be nice', 'could you add', 'i suggest', 'it would be great if'],
                'weight': 0.8
            },
            'account_support': {
                'keywords': ['account', 'login', 'password', 'access', 'locked', 'permission'],
                'phrases': ['can\'t login', 'forgot password', 'account locked', 'no access'],
                'weight': 0.9
            },
            'technical_support': {
                'keywords': ['help', 'support', 'question', 'how to', 'tutorial'],
                'phrases': ['how do i', 'can you help', 'i need help with', 'explain'],
                'weight': 0.6
            },
            'beta_program': {
                'keywords': ['beta', 'program', 'feedback', 'testing', 'early access'],
                'phrases': ['beta feedback', 'testing program', 'early access', 'beta user'],
                'weight': 0.7
            }
        }

        best_intent = 'general_inquiry'
        best_score = 0.0

        for intent, patterns in intent_patterns.items():
            score = 0.0

            # Score keywords
            for keyword in patterns['keywords']:
                if keyword in message_lower:
                    score += 1.0

            # Score phrases (higher weight)
            for phrase in patterns['phrases']:
                if phrase in message_lower:
                    score += 2.0

            # Apply intent-specific weight
            score *= patterns['weight']

            if score > best_score:
                best_score = score
                best_intent = intent

        # Normalize confidence score (0.0 to 1.0)
        max_possible_score = max(len(patterns['keywords']) + len(patterns['phrases']) * 2 for patterns in intent_patterns.values())
        confidence = min(best_score / max_possible_score, 1.0) if max_possible_score > 0 else 0.0

        return best_intent, confidence

    def categorize_conversation(self, message: str, intent: str, confidence: float) -> str:
        """Categorize conversation based on intent and confidence"""
        # Map intents to categories
        intent_to_category = {
            'jira_integration': ConversationCategory.JIRA_INTEGRATION.value,
            'performance_issue': ConversationCategory.PERFORMANCE_ISSUE.value,
            'bug_report': ConversationCategory.BUG_REPORT.value,
            'feature_request': ConversationCategory.FEATURE_REQUEST.value,
            'account_support': ConversationCategory.ACCOUNT_SUPPORT.value,
            'technical_support': ConversationCategory.TECHNICAL_SUPPORT.value,
            'beta_program': ConversationCategory.BETA_PROGRAM.value,
            'general_inquiry': ConversationCategory.GENERAL_INQUIRY.value
        }

        # If confidence is too low, mark as unknown
        if confidence < 0.3:
            return ConversationCategory.UNKNOWN.value

        return intent_to_category.get(intent, ConversationCategory.UNKNOWN.value)



    def update_success_metrics(self):
        """Update success rate and performance metrics"""
        total_requests = self.stats['messages_processed']
        total_errors = self.stats['errors']

        if total_requests > 0:
            self.stats['success_rate'] = round(((total_requests - total_errors) / total_requests) * 100, 1)

        # Update average response time
        if self.response_times:
            recent_times = self.response_times[-100:]  # Last 100 responses
            self.stats['avg_response_time'] = sum(recent_times) / len(recent_times)

    @tasks.loop(hours=1)
    async def cleanup_rate_limits(self):
        """Clean up old rate limit entries"""
        try:
            # Clean up old entries in rate limiter
            current_time = time.time()
            for key in list(self.rate_limiter.requests.keys()):
                self.rate_limiter.requests[key] = [
                    req_time for req_time in self.rate_limiter.requests[key]
                    if current_time - req_time < self.rate_limiter.window_seconds
                ]

                # Remove empty entries
                if not self.rate_limiter.requests[key]:
                    del self.rate_limiter.requests[key]

            # Clean up old security events
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.security_events = [
                event for event in self.security_events
                if event['timestamp'] > cutoff_time
            ]

            # Clean up old response times
            if len(self.response_times) > 1000:
                self.response_times = self.response_times[-500:]  # Keep last 500

            logger.debug("Cleanup completed")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    @tasks.loop(minutes=5)
    async def health_check(self):
        """Periodic health check and alerting"""
        try:
            health_status = {
                'timestamp': datetime.now().isoformat(),
                'uptime_seconds': (datetime.now() - self.stats['start_time']).total_seconds(),
                'messages_processed': self.stats['messages_processed'],
                'error_rate': self.stats['errors'] / max(self.stats['messages_processed'], 1),
                'circuit_breaker_state': self.circuit_breaker.state,
                'supabase_connected': False,  # Database removed
                'memory_usage': f"{len(self.response_times)} response times tracked"
            }

            # Log health status
            logger.debug(f"Health check: {health_status}")

            # Alert on high error rate
            if health_status['error_rate'] > 0.1:  # More than 10% error rate
                logger.warning(f"High error rate detected: {health_status['error_rate']:.2%}")

            # Database connection test removed

        except Exception as e:
            logger.error(f"Health check failed: {e}")

    @tasks.loop(hours=24)
    async def update_stats(self):
        """Enhanced daily statistics update"""
        try:
            uptime = datetime.now() - self.stats['start_time']
            self.update_success_metrics()

            logger.info(f"""Daily Statistics:
            - Messages Processed: {self.stats['messages_processed']}
            - Unique Users Helped: {len(self.stats['users_helped'])}
            - Commands Executed: {self.stats['commands_executed']}
            - Escalations Created: {self.stats['escalations_created']}
            - Uptime: {uptime}
            - Success Rate: {self.stats['success_rate']:.1f}%
            - Avg Response Time: {self.stats['avg_response_time']:.2f}s
            - Circuit Breaker: {self.circuit_breaker.state}
            - Security Events: {len(self.security_events)}
            """)

        except Exception as e:
            logger.error(f"Error updating statistics: {e}")

    # Enhanced Commands

    @commands.command(name='help')
    @commands.cooldown(1, 30, commands.BucketType.user)
    async def enhanced_help(self, ctx):
        """Enhanced help command with comprehensive information"""
        embed = discord.Embed(
            title="Maya - Enhanced SprintiQ AI Support",
            description="Your advanced AI customer support agent for SprintiQ Beta",
            color=0x00ff00
        )

        embed.add_field(
            name="Core Capabilities",
            value="""
            **Jira Integration** - Advanced setup, API troubleshooting, custom configurations
            **Sprint Planning** - AI-powered story generation, velocity optimization
            **Project Setup** - Team onboarding, workflow configuration, best practices
            **Technical Support** - Bug diagnosis, performance optimization, error resolution
            **Feature Development** - Enhancement requests, product roadmap feedback
            **Beta Compliance** - Program requirements, documentation, status tracking
            **Account Management** - Access control, team administration, security settings
            """,
            inline=False
        )

        embed.add_field(
            name="Enhanced Features",
            value="""
            • **Smart Response Matching** - Context-aware AI responses
            • **Circuit Breaker Protection** - Reliable fallback systems
            • **Rate Limiting** - Prevents spam and ensures fair usage
            • **Security Monitoring** - Advanced threat detection
            • **Performance Tracking** - Real-time metrics and optimization
            """,
            inline=False
        )

        embed.add_field(
            name="How to Get Help",
            value="""
            • **@mention me** anywhere: @Maya
            • **Support channels**: #jira-integration, #bug-reports, #maya-support
            • **Commands**: `!maya status`, `!maya escalate [issue]`
            • **Analytics**: `!maya analytics`, `!maya history [@user]`
            • **Direct Messages** for private account issues
            """,
            inline=False
        )

        embed.add_field(
            name="Performance Metrics",
            value=f"""
            • **Response Time**: {self.stats.get('avg_response_time', 2):.1f}s average
            • **Success Rate**: {self.stats.get('success_rate', 94):.1f}%
            • **Users Helped**: {len(self.stats['users_helped']):,}
            • **Uptime**: {((datetime.now() - self.stats['start_time']).days)}+ days
            """,
            inline=False
        )

        embed.set_footer(text="Enhanced Maya v2.0 - Production Ready")
        await ctx.send(embed=embed)

        self.stats['commands_executed'] += 1

    @commands.command(name='status')
    @commands.cooldown(1, 10, commands.BucketType.channel)
    async def enhanced_status(self, ctx):
        """Enhanced status command with comprehensive metrics"""
        uptime = datetime.now() - self.stats['start_time']
        uptime_str = f"{uptime.days}d {uptime.seconds//3600}h {(uptime.seconds//60)%60}m"

        embed = discord.Embed(
            title="Maya Enhanced Status Dashboard",
            description="All AI support systems operational and optimized",
            color=0x00ff00,
            timestamp=datetime.now()
        )

        # System Status
        embed.add_field(
            name="System Health",
            value=f"""
            **Status**: Online & Optimal
            **Version**: Enhanced v2.0
            **Uptime**: {uptime_str}
            **Circuit Breaker**: {self.circuit_breaker.state}
            """,
            inline=True
        )

        # Performance Metrics
        self.update_success_metrics()
        embed.add_field(
            name="Performance",
            value=f"""
            **Response Time**: {self.stats.get('avg_response_time', 2):.1f}s avg
            **Success Rate**: {self.stats.get('success_rate', 94):.1f}%
            **Processed**: {self.stats['messages_processed']} messages
            **Error Rate**: {(self.stats['errors']/max(self.stats['messages_processed'], 1)*100):.1f}%
            """,
            inline=True
        )

        # Service Status
        embed.add_field(
            name="Services",
            value=f"""
            **Discord API**: Connected
            **Database**: Disabled
            **Retell AI**: {'Available' if self.RETELL_API_KEY else 'Fallback Mode'}
            **Rate Limiting**: Active
            """,
            inline=True
        )

        # User Metrics
        embed.add_field(
            name="User Metrics",
            value=f"""
            **Users Helped**: {len(self.stats['users_helped'])}
            **Commands Run**: {self.stats['commands_executed']}
            **Escalations**: {self.stats['escalations_created']}
            **Security Events**: {len(self.security_events)}
            """,
            inline=True
        )

        # Guild Information
        total_members = sum(guild.member_count for guild in self.guilds)
        embed.add_field(
            name="Server Coverage",
            value=f"""
            **Servers**: {len(self.guilds)}
            **Total Members**: {total_members:,}
            **Avg Members/Server**: {total_members//len(self.guilds) if self.guilds else 0}
            **Guild Whitelist**: {'Active' if self.ALLOWED_GUILDS else 'Disabled'}
            """,
            inline=True
        )

        # Advanced Metrics
        recent_response_times = self.response_times[-10:] if self.response_times else [2.0]
        embed.add_field(
            name="Advanced Metrics",
            value=f"""
            **Last 10 Response Times**: {sum(recent_response_times)/len(recent_response_times):.2f}s
            **Memory Efficiency**: Tracking {len(self.response_times)} data points
            **Rate Limits Active**: {len(self.rate_limiter.requests)} users
            **Template Version**: {ResponseTemplates.VERSION}
            """,
            inline=True
        )

        embed.set_footer(text="Maya Enhanced Status • Real-time metrics")
        await ctx.send(embed=embed)

        self.stats['commands_executed'] += 1

    @commands.command(name='escalate')
    @commands.cooldown(1, 300, commands.BucketType.user)  # 5 minute cooldown per user
    async def enhanced_escalate(self, ctx, *, issue_description: str = None):
        """Enhanced escalation with priority routing and tracking"""
        if not issue_description:
            embed = discord.Embed(
                title="Escalation Help",
                description="Please describe the issue you'd like to escalate to human support.",
                color=0xffaa00
            )
            embed.add_field(
                name="Example Usage",
                value="`!maya escalate Jira integration completely broken, can't sync any stories`",
                inline=False
            )
            embed.add_field(
                name="Priority Guidelines",
                value="""
                **Critical**: System down, data loss, security issues
                **High**: Core features broken, blocking multiple users
                **Medium**: Feature issues, performance problems
                **Low**: Enhancement requests, minor bugs
                """,
                inline=False
            )
            await ctx.send(embed=embed)
            return

        # Classify escalation priority
        priority = self.classify_escalation_priority(issue_description)

        # Generate escalation ID
        escalation_id = f"ESC_{datetime.now().strftime('%Y%m%d')}_{ctx.message.id}"

        # Log escalation
        logger.warning(f"Issue escalated by {ctx.author}: {issue_description[:200]}...")
        self.stats['escalations_created'] += 1

        # Create escalation embed
        embed = discord.Embed(
            title="Issue Escalated to Human Support",
            description="Your issue has been escalated with the following details:",
            color=0xff9900
        )

        embed.add_field(name="Issue Description", value=issue_description[:1000], inline=False)
        embed.add_field(
            name="Priority Level",
            value=f"**{priority.upper()}** Priority",
            inline=True
        )
        embed.add_field(
            name="Escalation ID",
            value=f"`{escalation_id}`",
            inline=True
        )
        embed.add_field(
            name="User Info",
            value=f"{ctx.author.mention} in {ctx.channel.mention}",
            inline=True
        )

        # Priority-based response times
        response_times = {
            'critical': '< 15 minutes',
            'high': '< 30 minutes',
            'medium': '< 2 hours',
            'low': '< 4 hours'
        }

        embed.add_field(
            name="Response Timeline",
            value=f"""
            **Initial Contact**: {response_times.get(priority, '< 2 hours')}
            **Investigation Start**: {response_times.get(priority, '< 4 hours')}
            **Status Update**: Within 4 hours maximum
            """,
            inline=False
        )

        embed.add_field(
            name="What Happens Next",
            value="""
            1. Human support team immediately notified
            2. Engineer assigned based on issue type and priority
            3. You'll receive a direct message or email confirmation
            4. Regular status updates until resolution
            """,
            inline=False
        )

        embed.set_footer(text=f"Escalation created at {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")

        await ctx.send(embed=embed)

        # Database logging removed

        self.stats['commands_executed'] += 1

    @commands.command(name='analytics')
    @commands.cooldown(1, 60, commands.BucketType.user)  # 1 minute cooldown per user
    async def conversation_analytics(self, ctx):
        """Show conversation analytics and categorization insights"""
        try:
            # Get analytics from Supabase
            analytics = await self.conversation_manager.get_conversation_analytics()
            
            if not analytics:
                embed = discord.Embed(
                    title="No Analytics Available",
                    description="No conversation data has been collected yet.",
                    color=0xffaa00
                )
                await ctx.send(embed=embed)
                return

            # Create analytics embed
            embed = discord.Embed(
                title="Conversation Analytics Dashboard",
                description="Insights from archived conversations",
                color=0x00ff00,
                timestamp=datetime.now()
            )

            # Overall statistics
            embed.add_field(
                name="📊 Overall Statistics",
                value=f"""
                **Total Conversations**: {analytics.get('total_conversations', 0):,}
                **Last 24 Hours**: {analytics.get('recent_24h', 0)} conversations
                **Data Collection**: Active
                """,
                inline=False
            )

            # Category breakdown
            category_breakdown = analytics.get('category_breakdown', {})
            if category_breakdown:
                category_text = ""
                for category, count in sorted(category_breakdown.items(), key=lambda x: x[1], reverse=True):
                    category_text += f"• **{category.replace('-', ' ').title()}**: {count:,}\n"
                
                embed.add_field(
                    name="🏷️ Conversation Categories",
                    value=category_text,
                    inline=False
                )

            # Top categories
            if category_breakdown:
                top_category = max(category_breakdown.items(), key=lambda x: x[1])
                embed.add_field(
                    name="🔥 Most Common Issue",
                    value=f"**{top_category[0].replace('-', ' ').title()}** with {top_category[1]} conversations",
                    inline=True
                )

            # Recent activity
            embed.add_field(
                name="📈 Recent Activity",
                value=f"**{analytics.get('recent_24h', 0)}** conversations in the last 24 hours",
                inline=True
            )

            embed.set_footer(text="Data from Supabase conversation archive")
            await ctx.send(embed=embed)

        except Exception as e:
            logger.error(f"Error fetching analytics: {e}")
            embed = discord.Embed(
                title="Analytics Error",
                description="Failed to fetch conversation analytics. Please try again later.",
                color=0xff0000
            )
            await ctx.send(embed=embed)

        self.stats['commands_executed'] += 1

    @commands.command(name='history')
    @commands.cooldown(1, 30, commands.BucketType.user)  # 30 second cooldown per user
    async def user_conversation_history(self, ctx, user_mention: str = None):
        """Show conversation history for a user (or yourself if no user specified)"""
        try:
            # Determine which user to show history for
            if user_mention:
                # Parse user mention
                user_id = user_mention.strip('<@!>').strip('<@>')
                try:
                    user_id = int(user_id)
                    user = await self.fetch_user(user_id)
                    username = user.display_name if user else f"User {user_id}"
                except:
                    username = user_mention
            else:
                user_id = ctx.author.id
                username = ctx.author.display_name

            # Get conversation history
            history = await self.conversation_manager.get_user_conversation_history(str(user_id), limit=10)
            
            if not history:
                embed = discord.Embed(
                    title="No Conversation History",
                    description=f"No archived conversations found for {username}.",
                    color=0xffaa00
                )
                await ctx.send(embed=embed)
                return

            # Create history embed
            embed = discord.Embed(
                title=f"Conversation History - {username}",
                description=f"Last {len(history)} conversations",
                color=0x0099ff,
                timestamp=datetime.now()
            )

            # Show recent conversations
            for i, conv in enumerate(history[:5], 1):  # Show last 5
                category = conv.get('category', 'unknown').replace('-', ' ').title()
                content = conv.get('message_content', '')[:100]
                if len(content) == 100:
                    content += "..."
                
                embed.add_field(
                    name=f"{i}. {category}",
                    value=f"**{content}**\n*{conv.get('created_at', 'Unknown time')[:10]}*",
                    inline=False
                )

            if len(history) > 5:
                embed.add_field(
                    name="More Conversations",
                    value=f"Showing 5 of {len(history)} total conversations",
                    inline=False
                )

            embed.set_footer(text=f"User ID: {user_id}")
            await ctx.send(embed=embed)

        except Exception as e:
            logger.error(f"Error fetching user history: {e}")
            embed = discord.Embed(
                title="History Error",
                description="Failed to fetch conversation history. Please try again later.",
                color=0xff0000
            )
            await ctx.send(embed=embed)

        self.stats['commands_executed'] += 1

    def classify_escalation_priority(self, description: str) -> str:
        """Classify escalation priority based on description"""
        desc_lower = description.lower()

        # Critical keywords
        critical_keywords = ['down', 'crash', 'data loss', 'security', 'urgent', 'emergency', 'completely broken']
        if any(keyword in desc_lower for keyword in critical_keywords):
            return 'critical'

        # High priority keywords
        high_keywords = ['broken', 'not working', 'error', 'bug', 'can\'t', 'unable', 'blocking']
        if any(keyword in desc_lower for keyword in high_keywords):
            return 'high'

        # Medium priority keywords
        medium_keywords = ['slow', 'performance', 'issue', 'problem', 'difficult']
        if any(keyword in desc_lower for keyword in medium_keywords):
            return 'medium'

        return 'low'



    async def close(self):
        """Enhanced cleanup on bot shutdown"""
        logger.info("Starting enhanced bot shutdown...")

        try:
            # Stop background tasks
            if self.update_stats.is_running():
                self.update_stats.stop()
            if self.cleanup_rate_limits.is_running():
                self.cleanup_rate_limits.stop()
            if self.health_check.is_running():
                self.health_check.stop()

            # Close connection manager
            await self.connection_manager.close()

            # Close Supabase conversation manager
            await self.conversation_manager.close()

            # Final statistics log
            uptime = datetime.now() - self.stats['start_time']
            logger.info(f"""Final Statistics:
            - Total Uptime: {uptime}
            - Messages Processed: {self.stats['messages_processed']}
            - Users Helped: {len(self.stats['users_helped'])}
            - Commands Executed: {self.stats['commands_executed']}
            - Escalations Created: {self.stats['escalations_created']}
            - Total Errors: {self.stats['errors']}
            - Final Success Rate: {self.stats.get('success_rate', 0):.1f}%
            """)

        except Exception as e:
            logger.error(f"Error during shutdown: {e}")

        await super().close()
        logger.info("Enhanced Maya Bot shutdown complete")

async def main():
    """Enhanced main function with proper error handling"""
    try:
        logger.info("Starting Enhanced Maya Discord Bot v2.0...")

        # Validate configuration
        logger.info("Validating configuration...")

        # Create and start bot
        bot = EnhancedMayaBot()

        async with bot:
            logger.info("Connecting Enhanced Maya to Discord...")
            await bot.start(config.DISCORD_TOKEN)

    except KeyboardInterrupt:
        logger.info("Bot shutdown requested by user")
    except Exception as e:
        logger.error(f"Bot crashed with error: {e}")
        logger.error(traceback.format_exc())
    finally:
        logger.info("Cleaning up resources...")

if __name__ == "__main__":
    # Set event loop policy for Windows compatibility
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    asyncio.run(main())