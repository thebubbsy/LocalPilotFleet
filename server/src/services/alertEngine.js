/**
 * LocalPilot Fleet — Alert Dispatcher Engine
 * server/src/services/alertEngine.js
 *
 * Dispatches real-time security alerts:
 * - Native Windows Toast (WinRT)
 * - Discord, Slack, and Telegram webhooks
 * - Server-Sent Events (SSE) bus
 */

import { spawn } from 'node:child_process';
import os from 'node:os';
import logger from '../utils/logger.js';
import { broadcastEvent } from '../routes/events.js';

export async function sendWindowsToast(title, message) {
  if (os.platform() !== 'win32') return false;

  return new Promise(resolve => {
    // PowerShell script to invoke BurntToast or fallback Windows Toast via Windows.UI.Notifications
    const psScript = `
      $title = ${JSON.stringify(title)};
      $msg = ${JSON.stringify(message)};
      try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $textNodes = $template.GetElementsByTagName('text')
        $textNodes.Item(0).AppendChild($template.CreateTextNode($title)) | Out-Null
        $textNodes.Item(1).AppendChild($template.CreateTextNode($msg)) | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('LocalPilot.Fleet').Show($toast)
      } catch {
        # Fallback to simple console beep / notify
      }
    `;

    try {
      const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', psScript], {
        windowsHide: true
      });
      child.on('error', () => resolve(false));
      child.on('close', () => resolve(true));
      setTimeout(() => {
        child.kill();
        resolve(true);
      }, 2500);
    } catch {
      resolve(false);
    }
  });
}

export async function sendDiscordWebhook(url, eventRecord) {
  if (!url) return false;
  try {
    const payload = {
      embeds: [{
        title: `🚨 LocalPilot Security Alert: ${eventRecord.event_type}`,
        description: eventRecord.summary,
        color: eventRecord.severity === 'CRITICAL' ? 15158332 : 15105570,
        fields: [
          { name: 'Device ID', value: String(eventRecord.device_id), inline: true },
          { name: 'Severity', value: String(eventRecord.severity), inline: true },
          { name: 'Source', value: String(eventRecord.event_source), inline: true }
        ],
        timestamp: eventRecord.created_at || new Date().toISOString()
      }]
    };
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.ok;
  } catch (err) {
    logger.warn('Discord webhook dispatch failed', { error: err.message });
    return false;
  }
}

export async function sendSlackWebhook(url, eventRecord) {
  if (!url) return false;
  try {
    const payload = {
      text: `🚨 *[${eventRecord.severity}] ${eventRecord.event_type}*\n${eventRecord.summary}\nDevice: \`${eventRecord.device_id}\``
    };
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.ok;
  } catch (err) {
    logger.warn('Slack webhook dispatch failed', { error: err.message });
    return false;
  }
}

export async function sendTelegramNotification(botToken, chatId, eventRecord) {
  if (!botToken || !chatId) return false;
  try {
    const text = `🚨 *LocalPilot Security Alert*\n*Type:* ${eventRecord.event_type}\n*Severity:* ${eventRecord.severity}\n*Device:* ${eventRecord.device_id}\n\n${eventRecord.summary}`;
    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' })
    });
    return res.ok;
  } catch (err) {
    logger.warn('Telegram dispatch failed', { error: err.message });
    return false;
  }
}

export const alertEngine = {
  async dispatchAlert(eventRecord, settings = {}) {
    const results = {
      toast_fired: false,
      webhooks_dispatched: [],
      sse_broadcast: false
    };

    // 1. Broadcast via SSE immediately
    try {
      broadcastEvent('security_alert', eventRecord);
      results.sse_broadcast = true;
    } catch (err) {
      logger.warn('SSE broadcast error', { error: err.message });
    }

    // 2. Windows Native Toast
    const toastEnabled = settings.toast_notifications_enabled !== 'false' && settings.toast_notifications_enabled !== false;
    if (toastEnabled) {
      const title = `LocalPilot Alert: ${eventRecord.event_type} (${eventRecord.severity})`;
      results.toast_fired = await sendWindowsToast(title, eventRecord.summary);
    }

    // 3. Webhook integrations
    if (settings.discord_webhook_url) {
      const ok = await sendDiscordWebhook(settings.discord_webhook_url, eventRecord);
      if (ok) results.webhooks_dispatched.push('discord');
    }

    if (settings.slack_webhook_url) {
      const ok = await sendSlackWebhook(settings.slack_webhook_url, eventRecord);
      if (ok) results.webhooks_dispatched.push('slack');
    }

    if (settings.telegram_bot_token && settings.telegram_chat_id) {
      const ok = await sendTelegramNotification(settings.telegram_bot_token, settings.telegram_chat_id, eventRecord);
      if (ok) results.webhooks_dispatched.push('telegram');
    }

    return results;
  }
};

export default alertEngine;
