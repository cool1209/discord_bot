# Maya Discord Bot - Enhanced with Conversation Archiving

Maya is an advanced AI-powered Discord bot designed for SprintiQ customer support, now enhanced with comprehensive conversation archiving and categorization using Supabase.

## 🚀 Features

### Core AI Support

- **Jira Integration Support** - Setup, troubleshooting, API configuration
- **Sprint Planning Assistance** - AI-powered story generation and optimization
- **Technical Support** - Bug reports, performance issues, error resolution
- **Account Management** - Access control, team administration, security
- **Beta Program Support** - Requirements, compliance, documentation

### Conversation Archiving & Analytics

- **Automatic Categorization** - Every conversation is automatically classified
- **Supabase Storage** - All conversations stored in searchable database
- **User History Tracking** - Complete conversation history per user
- **Analytics Dashboard** - Real-time insights and statistics
- **Smart Intent Recognition** - ML-like scoring for accurate categorization

## 📊 Conversation Categories

The bot automatically categorizes conversations into:

- **bug-report** - Error reports, crashes, broken features
- **feature-request** - Enhancement requests, new functionality
- **jira-integration** - Jira sync issues, API problems, webhook setup
- **performance-issue** - Slow loading, timeouts, performance problems
- **account-support** - Login issues, permissions, account access
- **technical-support** - General help, how-to questions, tutorials
- **beta-program** - Beta feedback, testing, early access
- **general-inquiry** - General questions, information requests

## 🛠️ Setup Instructions

### 1. Prerequisites

- Python 3.8+
- Discord Bot Token
- Supabase Project (for conversation archiving)

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Environment Configuration

Copy `env.example` to `.env` and configure:

```bash
# Discord Bot Configuration
DISCORD_TOKEN=your_discord_bot_token_here
SPRINTIQ_DISCORD_GUILD_ID=your_guild_id_here

# Supabase Configuration (Required for conversation archiving)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_supabase_anon_key_here

# Optional: Retell AI for enhanced responses
RETELL_API_KEY=your_retell_api_key_here
```

### 4. Supabase Database Setup

1. Create a new Supabase project
2. Go to SQL Editor
3. Run the contents of `supabase_schema.sql`
4. Copy your project URL and anon key to `.env`
5. Test the connection: `python test_supabase.py`

### 5. Run the Bot

```bash
python main.py
```

## 📱 Commands

### Core Commands

- `!maya help` - Show all available commands and features
- `!maya status` - Display bot status and performance metrics
- `!maya escalate [issue]` - Escalate issue to human support

### Analytics Commands

- `!maya analytics` - Show conversation analytics dashboard
- `!maya history [@user]` - Display conversation history for a user

### Auto-Response Channels

The bot automatically responds in these channels:

- `#jira-integration` - Always responds to Jira-related questions
- `#bug-reports` - Always responds to bug reports
- `#maya-support` - Always responds to support requests
- `#general-beta` - Responds when support keywords are detected
- `#feedback` - Responds when feedback keywords are detected

## 🗄️ Database Schema

### Conversations Table

Stores all user interactions with:

- User identification and Discord context
- Message content and AI responses
- Automatic categorization and confidence scores
- Metadata including response times and bot state

### Users Table

Tracks user statistics including:

- Total conversation count
- First and last seen timestamps
- Preferred conversation categories
- Activity patterns

### Views and Functions

- `category_summary` - Category breakdown with statistics
- `user_activity` - User activity and conversation patterns
- `get_conversation_analytics()` - Analytics function for insights

## 🔍 Analytics Features

### Real-Time Insights

- **Total Conversations** - Complete conversation count
- **Category Breakdown** - Distribution across all categories
- **Recent Activity** - Last 24 hours of conversations
- **Top Issues** - Most common problem categories
- **User Engagement** - Individual user conversation patterns

### Data Export

All data is stored in Supabase and can be:

- Exported via SQL queries
- Accessed via Supabase dashboard
- Integrated with external analytics tools
- Used for customer success insights

## 🚨 Security Features

- **Rate Limiting** - Prevents spam and abuse
- **Input Validation** - Sanitizes all user input
- **Guild Whitelisting** - Restricts bot to authorized servers
- **Row Level Security** - Database-level access control
- **Audit Logging** - Complete conversation history tracking

## 📈 Performance Monitoring

- **Response Time Tracking** - Average response times
- **Success Rate Monitoring** - Error rate tracking
- **Circuit Breaker** - Automatic fallback for external services
- **Health Checks** - Periodic system health monitoring
- **Memory Management** - Efficient data structure usage

## 🔧 Configuration Options

### Rate Limiting

```bash
RATE_LIMIT_MESSAGES=5      # Messages per user
RATE_LIMIT_WINDOW=60       # Time window in seconds
```

### Performance

```bash
MAX_MESSAGE_LENGTH=2000    # Maximum message length
CONNECTION_POOL_SIZE=10    # HTTP connection pool size
```

### Security

```bash
ALLOWED_GUILDS=guild1,guild2    # Whitelisted Discord servers
ADMIN_USER_IDS=user1,user2      # Admin user IDs
```

## 🐛 Troubleshooting

### Common Issues

1. **Supabase Connection Failed**

   - Verify URL and API key in `.env`
   - Check Supabase project status
   - Ensure database schema is created
   - Run `python test_supabase.py` to test connection

2. **Bot Not Responding**

   - Check Discord bot permissions
   - Verify bot is in correct channels
   - Check rate limiting settings

3. **Conversations Not Archived**

   - Verify Supabase configuration
   - Check bot logs for errors
   - Ensure database tables exist
   - Check for "null value in column id" errors (fixed in v2.0)

4. **Database Schema Issues**
   - Ensure `supabase_schema.sql` was run completely
   - Check that tables `conversations` and `discord_users` exist
   - Verify Row Level Security policies are created

### Logs

Bot logs are stored in `logs/maya_bot.log` with:

- Conversation archiving status
- Error details and stack traces
- Performance metrics
- Security events

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is proprietary software for SprintiQ internal use.

## 🆘 Support

For technical support or questions about the bot:

- Use `!maya escalate [issue]` in Discord
- Check the logs for detailed error information
- Review the Supabase dashboard for data issues

---

**Maya v2.0** - Enhanced with conversation archiving and analytics
