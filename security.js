const CALENDAR_ORIGIN = 'https://calendar.google.com';
const APP_ORIGINS = new Set([CALENDAR_ORIGIN, 'https://accounts.google.com']);

const parseUrl = (value) => {
    try {
        return new URL(value);
    } catch {
        return null;
    }
};

const getHttpsOrigin = (value) => {
    const url = parseUrl(value);
    return url?.protocol === 'https:' && !url.username && !url.password ? url.origin : null;
};

const isAppUrl = (value) => APP_ORIGINS.has(getHttpsOrigin(value));
const isCalendarUrl = (value) => getHttpsOrigin(value) === CALENDAR_ORIGIN;

const configureSecurity = (mainWindow, openExternal) => {
    const contents = mainWindow.webContents;

    const openExternalLink = (value) => {
        const url = parseUrl(value);
        if (!url || url.username || url.password || !['https:', 'http:'].includes(url.protocol)) {
            return;
        }

        openExternal(url.href).catch(() => {
            console.error('Could not open the external web link.');
        });
    };

    contents.setWindowOpenHandler(({ url }) => {
        if (isAppUrl(url)) {
            contents.loadURL(url).catch(() => {
                console.error('Could not open the Google page.');
            });
        } else {
            openExternalLink(url);
        }
        return { action: 'deny' };
    });

    contents.on('will-navigate', (event) => {
        if (!isAppUrl(event.url)) {
            event.preventDefault();
            openExternalLink(event.url);
        }
    });

    // Redirects must stay within the app's trusted Google origins.
    contents.on('will-redirect', (event) => {
        if (event.isMainFrame && !isAppUrl(event.url)) {
            event.preventDefault();
        }
    });

    const allowNotification = (requestContents, permission, requestingUrl) => {
        return requestContents === contents &&
            permission === 'notifications' &&
            isCalendarUrl(contents.getURL()) &&
            isCalendarUrl(requestingUrl);
    };

    contents.session.setPermissionRequestHandler((requestContents, permission, callback, details) => {
        callback(allowNotification(requestContents, permission, details?.requestingUrl));
    });

    contents.session.setPermissionCheckHandler((requestContents, permission, requestingOrigin) => {
        return allowNotification(requestContents, permission, requestingOrigin);
    });
};

module.exports = { configureSecurity, isCalendarUrl };
