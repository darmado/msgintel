// Script Name: msgIntel.js
// MITRE ATT&CK Technique: T1005 - Data from Local System
// Platform: macOS

(() => {
    'use strict';
    
    ObjC.import('Foundation');
    ObjC.import('CoreServices');

    // At the top level, after imports
    const OUTPUT_FORMAT = {
        LINE: '-line',
        JSON: '-json',
        CSV: '-csv',
        COLUMN: '-column',
        HTML: '-html',
        INSERT: '-insert',
        LIST: '-list'
    };

    // Valid output formats as static array
    const VALID_OUTPUT_FORMATS = [
        'json',  // Default
        'line',
        'csv',
        'column',
        'html',
        'insert',
        'list'
    ];

    // Utility class for constants and shared functions
    class MsgIntelUtils {
        static SQLITE_BIN = '/usr/bin/sqlite3';
        static USER_INFO = {
            username: $.NSUserName().js,
            homeDir: $.NSHomeDirectory().js
        };
        
        static DBS = {
            chat: `${this.USER_INFO.homeDir}/Library/Messages/chat.db`,
            nicknames: `${this.USER_INFO.homeDir}/Library/Messages/NickNameCache/nickNameKeyStore.db`,
            collaborationNotices: `${this.USER_INFO.homeDir}/Library/Messages/CollaborationNoticeCache/collaborationNotices.db`,
            handleSharingPreferences: `${this.USER_INFO.homeDir}/Library/Messages/NickNameCache/handleSharingPreferences.db`,
            handledNicknamesKeyStore: `${this.USER_INFO.homeDir}/Library/Messages/NickNameCache/handledNicknamesKeyStore.db`,
            pendingNicknamesKeyStore: `${this.USER_INFO.homeDir}/Library/Messages/NickNameCache/pendingNicknamesKeyStore.db`,
            prewarmsg: `${this.USER_INFO.homeDir}/Library/Messages/prewarmsg.db`
        };

        // Add output format getter
        static get OUTPUT_FORMAT() {
            return OUTPUT_FORMAT;
        }

        // Add valid formats getter
        static get VALID_FORMATS() {
            return VALID_OUTPUT_FORMATS;
        }

        static mapCommunication(msg, handleData, destHandleData) {
            const isEmail = (id) => id && id.includes('@');
            
            return {
                sender: msg.is_from_me === 0 ? {
                    phone_number: isEmail(handleData?.id) ? null : handleData?.id,
                    email: isEmail(handleData?.id) ? handleData?.id : null,
                    country: handleData?.country,
                    handle_id: msg.handle_id
                } : {
                    phone_number: isEmail(msg.destination_caller_id) ? null : msg.destination_caller_id,
                    email: isEmail(msg.destination_caller_id) ? msg.destination_caller_id : null,
                    country: destHandleData?.country,
                    handle_id: null
                },
                receiver: msg.is_from_me === 1 ? {
                    phone_number: isEmail(handleData?.id) ? null : handleData?.id,
                    email: isEmail(handleData?.id) ? handleData?.id : null,
                    country: handleData?.country,
                    handle_id: msg.handle_id
                } : {
                    phone_number: isEmail(msg.destination_caller_id) ? null : msg.destination_caller_id,
                    email: isEmail(msg.destination_caller_id) ? msg.destination_caller_id : null,
                    country: destHandleData?.country,
                    handle_id: null
                }
            };
        }

        static convertAppleDate(timestamp) {
            if (!timestamp) return null;
            
            // Case 1: Cocoa timestamp (nanoseconds since 2001)
            if (timestamp > 1000000000000) {
                const unixTimestamp = Math.floor(timestamp / 1000000000 + 978307200);
                return new Date(unixTimestamp * 1000).toISOString();
            }
            
            // Case 2: Attachment timestamps (seconds since 2001)
            if (timestamp < 1000000000) {
                return new Date((timestamp + 978307200) * 1000).toISOString();
            }
            
            // Case 3: Standard Unix timestamp
            return new Date(timestamp * 1000).toISOString();
        }

        static formatOutput(data, format = OUTPUT_FORMAT.JSON) {
            // If not JSON format, return raw data as tab-delimited rows with headers
            if (format !== OUTPUT_FORMAT.JSON) {
                if (!data || !data.data || !data.data.messages) return '';
                
                // Define headers
                const headers = [
                    'GUID',
                    'MESSAGE',
                    'DATE',
                    'SERVICE',
                    'SENDER',
                    'RECEIVER'
                ].join('\t');

                // Format data rows
                const rows = data.data.messages.map(msg => {
                    const m = msg.message;
                    return [
                        m.guid,
                        m.content.text,
                        m.timestamps.date,
                        m.communication.channel.service,
                        m.communication.sender.phone_number || m.communication.sender.email || '',
                        m.communication.receiver.phone_number || m.communication.receiver.email || ''
                    ].join('\t');
                });

                // Combine headers and rows
                return [headers, ...rows].join('\n');
            }

            // Return formatted JSON
            return JSON.stringify(data, null, 2);
        }
    }

    // TCC Check Function
    function Check() {
        ObjC.import('CoreServices')
        ObjC.bindFunction('CFMakeCollectable', ['id', ['void *']])
        
        const homeDir = $.NSHomeDirectory().js;
        const tccDbPath = `${homeDir}/Library/Application Support/com.apple.TCC/TCC.db`;
        const queryString = "kMDItemDisplayName = *TCC.db";
        
        let query = $.MDQueryCreate($(), $(queryString), $(), $());
        let queryExecuteResult = $.MDQueryExecute(query, 1);
        let resultCount = $.MDQueryGetResultCount(query);
        
        const status = {
            tcc: {
                granted: false,
                path: tccDbPath,
                query_success: queryExecuteResult,
                query_results: resultCount
            },
            process: {
                name: $.NSProcessInfo.processInfo.processName.js,
                pid: $.NSProcessInfo.processInfo.processIdentifier
            }
        };

        if (queryExecuteResult) {
            for (var i = 0; i < resultCount; i++) {
                var mdItem = $.MDQueryGetResultAtIndex(query, i);
                var mdAttrs1 = $.MDItemCopyAttribute($.CFMakeCollectable(mdItem), $.kMDItemPath)
                var mdAttrs = ObjC.deepUnwrap(mdAttrs1);
                if (mdAttrs === tccDbPath) {
                    status.tcc.granted = true;
                    break;
                }
            }
        }

        console.log(JSON.stringify(status, null, 2));
        return status.tcc.granted;
    }

    // Base Database Class
    class BaseDB {
        constructor(dbPath) {
            this.dbPath = dbPath;
            this.task = $.NSTask.alloc.init;
            this.pipe = $.NSPipe.pipe;
        }

        query(sql, format = OUTPUT_FORMAT.JSON) {
            try {
                const task = $.NSTask.alloc.init;
                task.launchPath = MsgIntelUtils.SQLITE_BIN;
                task.arguments = [this.dbPath, format, sql];
                
                const pipe = $.NSPipe.pipe;
                task.standardOutput = pipe;
                task.standardError = pipe;
                
                task.launch;
                const data = pipe.fileHandleForReading.readDataToEndOfFile;
                const output = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js;
                
                return format === OUTPUT_FORMAT.JSON ? JSON.parse(output) : output;
            } catch(e) {
                return null;
            }
        }
    }

    // Messages Class
    class Messages extends BaseDB {
        constructor() {
            super(MsgIntelUtils.DBS.chat);
            // Cache handles on init for faster lookups
            this.handles = this.getHandles();
        }

        // Cache handles for faster lookups
        getHandles() {
            const sql = `SELECT ROWID, id, country FROM handle;`;
            const results = this.query(sql);
            return {
                byRowId: new Map(results.map(h => [h.ROWID, h])),
                byId: new Map(results.map(h => [h.id, h]))
            };
        }

        getMessages(format = OUTPUT_FORMAT.JSON) {
            const sql = `SELECT 
                m.ROWID, m.guid, m.text, m.service, m.handle_id, 
                m.is_from_me, m.destination_caller_id,
                m.service_center, m.version, m.account, m.account_guid,
                m.date, m.date_played, m.date_retracted, m.date_edited,
                m.subject, m.group_title,
                m.associated_message_guid, m.reply_to_guid, m.thread_originator_guid,
                m.is_delivered, m.is_read, m.is_sent, m.is_played, m.is_prepared, m.is_finished,
                m.is_empty, m.is_archive, m.is_spam, m.is_corrupt, m.is_expirable,
                m.is_system_message, m.is_service_message, m.is_forward, m.is_audio_message, m.is_emote,
                m.was_data_detected, m.was_delivered_quietly, m.was_detonated,
                m.ck_sync_state, m.ck_record_id, m.ck_record_change_tag,
                c.chat_identifier
            FROM message m
            LEFT JOIN chat_message_join cmj ON m.ROWID = cmj.message_id
            LEFT JOIN chat c ON cmj.chat_id = c.ROWID
            WHERE m.text IS NOT NULL;`;

            const results = this.query(sql);
            
            if (format !== OUTPUT_FORMAT.JSON) {
                return results;
            } 

            if (!results) return [];

            
            return {
                job: {
                    job_id: `JOB-${$.NSProcessInfo.processInfo.processIdentifier}`,
                    user: MsgIntelUtils.USER_INFO.username,
                    executor: "osascript", // TODO: get executor value from current app
                    language: "jxa",
                    imports: ["Foundation", "CoreServices"],
                    binaries: ["sqlite3"], // TODO: get binaries from the const 
                    pid: $.NSProcessInfo.processInfo.processIdentifier,
                    query: {
                        timestamp: new Date().toISOString(),
                        source_db: this.dbPath,
                        type: "messages"
                    }
                },
                data: {
                    messages: results ? results.map(msg => ({
                        message: {
                            guid: msg.guid,
                            timestamps: {
                                date: MsgIntelUtils.convertAppleDate(msg.date),
                                date_read: MsgIntelUtils.convertAppleDate(msg.date_read),
                                date_delivered: MsgIntelUtils.convertAppleDate(msg.date_delivered),
                                date_played: MsgIntelUtils.convertAppleDate(msg.date_played),
                                date_retracted: MsgIntelUtils.convertAppleDate(msg.date_retracted),
                                date_edited: MsgIntelUtils.convertAppleDate(msg.date_edited)
                            },
                            type: {
                                is_empty: Boolean(msg.is_empty),
                                is_archive: Boolean(msg.is_archive),
                                is_spam: Boolean(msg.is_spam),
                                is_corrupt: Boolean(msg.is_corrupt),
                                is_expirable: Boolean(msg.is_expirable),
                                is_system: Boolean(msg.is_system_message),
                                is_service: Boolean(msg.is_service_message),
                                is_forward: Boolean(msg.is_forward),
                                is_audio: Boolean(msg.is_audio_message),
                                is_emote: Boolean(msg.is_emote)
                            },
                            state: {
                                is_delivered: Boolean(msg.is_delivered),
                                is_read: Boolean(msg.is_read),
                                is_sent: Boolean(msg.is_sent),
                                is_played: Boolean(msg.is_played),
                                is_prepared: Boolean(msg.is_prepared),
                                is_finished: Boolean(msg.is_finished),
                                is_empty: Boolean(msg.is_empty),
                                was_data_detected: Boolean(msg.was_data_detected),
                                was_delivered_quietly: Boolean(msg.was_delivered_quietly),
                                was_detonated: Boolean(msg.was_detonated)
                            },
                            communication: {
                                channel: {
                                    service: msg.service,
                                    version: msg.version,
                                    is_from_me: msg.is_from_me,
                                    chat_identifier: msg.chat_identifier,
                                    thread: {
                                        reply_to_guid: msg.reply_to_guid,
                                        originator_guid: msg.thread_originator_guid,
                                        associated_guid: msg.associated_message_guid
                                    }
                                },
                                sender: msg.is_from_me === 0 ? {
                                    phone_number: this.handles.byRowId.get(msg.handle_id)?.id.includes('@') ? null : this.handles.byRowId.get(msg.handle_id)?.id,
                                    email: this.handles.byRowId.get(msg.handle_id)?.id.includes('@') ? this.handles.byRowId.get(msg.handle_id)?.id : null,
                                    country: this.handles.byRowId.get(msg.handle_id)?.country,
                                    handle_id: msg.handle_id
                                } : {
                                    phone_number: msg.destination_caller_id?.includes('@') ? null : msg.destination_caller_id,
                                    email: msg.destination_caller_id?.includes('@') ? msg.destination_caller_id : null,
                                    country: this.handles.byId.get(msg.destination_caller_id)?.country,
                                    handle_id: null
                                },
                                receiver: msg.is_from_me === 1 ? {
                                    phone_number: this.handles.byRowId.get(msg.handle_id)?.id.includes('@') ? null : this.handles.byRowId.get(msg.handle_id)?.id,
                                    email: this.handles.byRowId.get(msg.handle_id)?.id.includes('@') ? this.handles.byRowId.get(msg.handle_id)?.id : null,
                                    country: this.handles.byRowId.get(msg.handle_id)?.country,
                                    handle_id: msg.handle_id
                                } : {
                                    phone_number: msg.destination_caller_id?.includes('@') ? null : msg.destination_caller_id,
                                    email: msg.destination_caller_id?.includes('@') ? msg.destination_caller_id : null,
                                    country: this.handles.byId.get(msg.destination_caller_id)?.country,
                                    handle_id: null
                                }
                            },
                            content: {
                                text: msg.text,
                                subject: msg.subject,
                                group_title: msg.group_title,
                            },
                            icloud: {
                                ck_sync_state: msg.ck_sync_state,
                                ck_record_id: msg.ck_record_id,
                                ck_record_change_tag: msg.ck_record_change_tag
                            }
                        }
                    })) : []
                }
            };
        }

        getContacts() {
            const sql = `SELECT h.ROWID, h.id, h.service, h.uncanonicalized_id, COUNT(m.ROWID) as message_count FROM handle h LEFT JOIN message m ON h.ROWID = m.handle_id GROUP BY h.ROWID;`;
            return this.query(sql);
        }

        getThreads() {
            const sql = `SELECT c.ROWID, c.guid, c.style, COUNT(cm.message_id) as message_count, MAX(m.date) as last_message_date FROM chat c LEFT JOIN chat_message_join cm ON c.ROWID = cm.chat_id LEFT JOIN message m ON cm.message_id = m.ROWID GROUP BY c.ROWID;`;
            return this.query(sql);
        }
    }

    // Attachments Class
    class Attachments extends BaseDB {
        constructor() {
            super(MsgIntelUtils.DBS.chat);
            this.handles = this.getHandles();
        }

        getHandles() {
            const sql = `SELECT ROWID, id, country FROM handle;`;
            const results = this.query(sql);
            return {
                byRowId: new Map(results.map(h => [h.ROWID, h])),
                byId: new Map(results.map(h => [h.id, h]))
            };
        }

        getAttachments(format = OUTPUT_FORMAT.JSON) {
            const sql = `SELECT 
                a.ROWID,
                a.guid,
                a.created_date,
                a.filename,
                a.mime_type,
                a.transfer_state,
                a.is_outgoing,
                a.is_sticker,
                a.hide_attachment,
                a.is_commsafety_sensitive,
                a.ck_sync_state,
                a.original_guid,
                a.ck_record_id,
                m.handle_id,
                m.is_from_me,
                m.destination_caller_id,
                m.is_delivered,
                m.is_read,
                m.is_sent,
                m.is_empty,
                m.is_delayed,
                m.is_auto_reply,
                m.is_prepared,
                m.is_finished,
                m.is_spam,
                m.is_kt_verified
            FROM attachment a
            LEFT JOIN message_attachment_join maj ON a.ROWID = maj.attachment_id
            LEFT JOIN message m ON maj.message_id = m.ROWID
            ORDER BY a.ROWID ASC;`;

            const results = this.query(sql, format);

            if (format !== OUTPUT_FORMAT.JSON) {
                return results;
            }

            if (!results) return [];

            return {
                job: {
                    job_id: `JOB-${$.NSProcessInfo.processInfo.processIdentifier}`,
                    user: MsgIntelUtils.USER_INFO.username,
                    executor: "osascript",
                    language: "jxa",
                    imports: ["Foundation", "CoreServices"],
                    binaries: ["sqlite3"],
                    pid: $.NSProcessInfo.processInfo.processIdentifier,
                    query: {
                        timestamp: new Date().toISOString(),
                        source_db: this.dbPath,
                        type: "discover"
                    }
                },
                attachments: results.map(att => ({
                    attachment: {
                        guid: att.guid,
                        created_date: MsgIntelUtils.convertAppleDate(att.created_date),
                        metadata: {
                            filename: att.filename,
                            mime_type: att.mime_type,
                            uti: att.uti,
                            transfer_name: att.transfer_name,
                            total_bytes: att.total_bytes
                        },
                        status: {
                            transfer_state: att.transfer_state,
                            is_outgoing: att.is_outgoing,
                            is_sticker: att.is_sticker,
                            hide_attachment: att.hide_attachment,
                            is_commsafety_sensitive: att.is_commsafety_sensitive,
                            ck_sync_state: att.ck_sync_state
                        },
                        message: {
                            guid: att.guid.substring(att.guid.indexOf('_', att.guid.indexOf('_') + 1) + 1),
                            is_from_me: att.is_from_me,
                            communication: MsgIntelUtils.mapCommunication(att, 
                                this.handles.byRowId.get(att.handle_id),
                                this.handles.byId.get(att.destination_caller_id)),
                            state: {
                                is_delivered: Boolean(att.is_delivered),
                                is_read: Boolean(att.is_read),
                                is_sent: Boolean(att.is_sent),
                                is_spam: Boolean(att.is_spam),
                                is_kt_verified: Boolean(att.is_kt_verified)
                            }
                        }
                    }
                }))
            };
        }
    }

    // Search Class
    class Search extends BaseDB {
        constructor() {
            super(MsgIntelUtils.DBS.chat);
            this.handles = this.getHandles();  // Initialize handles cache like Messages class
        }

        getHandles() {
            const sql = `SELECT ROWID, id, country FROM handle;`;
            const results = this.query(sql);
            return {
                byRowId: new Map(results.map(h => [h.ROWID, h])),
                byId: new Map(results.map(h => [h.id, h]))
            };
        }

        searchAll(inputStr, format = OUTPUT_FORMAT.JSON) {
            const escapedInputStr = inputStr.replace(/_/g, '\\_').replace(/%/g, '\\%');

            const msgSql = `SELECT 
                m.ROWID, m.guid, m.text, m.service, m.handle_id,
                m.is_from_me, m.destination_caller_id,
                m.service_center, m.version,
                m.date, m.date_read, m.date_delivered, m.date_played, m.date_retracted, m.date_edited,
                m.subject, m.group_title,
                m.associated_message_guid, m.reply_to_guid, m.thread_originator_guid,
                m.is_delivered, m.is_read, m.is_sent, m.is_played, m.is_prepared, m.is_finished,
                m.is_empty, m.is_archive, m.is_spam, m.is_corrupt, m.is_expirable,
                m.is_system_message, m.is_service_message, m.is_forward, m.is_audio_message, m.is_emote,
                m.was_data_detected, m.was_delivered_quietly, m.was_detonated,
                m.ck_sync_state, m.ck_record_id, m.ck_record_change_tag,
                c.chat_identifier
            FROM message m 
            LEFT JOIN chat_message_join cmj ON m.ROWID = cmj.message_id
            LEFT JOIN chat c ON cmj.chat_id = c.ROWID
            LEFT JOIN handle h ON m.handle_id = h.ROWID
            WHERE m.text LIKE '%${escapedInputStr}%'
            OR m.guid LIKE '%${escapedInputStr}%'
            OR h.id LIKE '%${escapedInputStr}%'
            OR m.destination_caller_id LIKE '%${escapedInputStr}%';`;

            const messages = this.query(msgSql);

            const output = {
                job: {
                    job_id: `JOB-${$.NSProcessInfo.processInfo.processIdentifier}`,
                    user: MsgIntelUtils.USER_INFO.username,
                    executor: "osascript",
                    language: "jxa",
                    imports: ["Foundation", "CoreServices"],
                    binaries: ["sqlite3"],
                    pid: $.NSProcessInfo.processInfo.processIdentifier,
                    query: {
                        timestamp: new Date().toISOString(),
                        source_db: this.dbPath,
                        type: "search",
                        inputStr: inputStr
                    }
                },
                data: {
                    messages: messages.map(msg => ({
                        message: {
                            guid: msg.guid,
                            timestamps: {
                                date: MsgIntelUtils.convertAppleDate(msg.date),
                                date_read: MsgIntelUtils.convertAppleDate(msg.date_read),
                                date_delivered: MsgIntelUtils.convertAppleDate(msg.date_delivered),
                                date_played: MsgIntelUtils.convertAppleDate(msg.date_played),
                                date_retracted: MsgIntelUtils.convertAppleDate(msg.date_retracted),
                                date_edited: MsgIntelUtils.convertAppleDate(msg.date_edited)
                            },
                            type: {
                                is_empty: Boolean(msg.is_empty),
                                is_archive: Boolean(msg.is_archive),
                                is_spam: Boolean(msg.is_spam),
                                is_corrupt: Boolean(msg.is_corrupt),
                                is_expirable: Boolean(msg.is_expirable),
                                is_system: Boolean(msg.is_system_message),
                                is_service: Boolean(msg.is_service_message),
                                is_forward: Boolean(msg.is_forward),
                                is_audio: Boolean(msg.is_audio_message),
                                is_emote: Boolean(msg.is_emote)
                            },
                            state: {
                                is_delivered: Boolean(msg.is_delivered),
                                is_read: Boolean(msg.is_read),
                                is_sent: Boolean(msg.is_sent),
                                is_played: Boolean(msg.is_played),
                                is_prepared: Boolean(msg.is_prepared),
                                is_finished: Boolean(msg.is_finished),
                                is_empty: Boolean(msg.is_empty),
                                was_data_detected: Boolean(msg.was_data_detected),
                                was_delivered_quietly: Boolean(msg.was_delivered_quietly),
                                was_detonated: Boolean(msg.was_detonated)
                            },
                            communication: {
                                channel: {
                                    service: msg.service,
                                    version: msg.version,
                                    is_from_me: msg.is_from_me,
                                    chat_identifier: msg.chat_identifier,
                                    thread: {
                                        reply_to_guid: msg.reply_to_guid,
                                        originator_guid: msg.thread_originator_guid,
                                        associated_guid: msg.associated_message_guid
                                    }
                                },
                                sender: msg.is_from_me === 0 ? {
                                    phone_number: this.handles.byRowId.get(msg.handle_id)?.id.includes('@') ? null : this.handles.byRowId.get(msg.handle_id)?.id,
                                    email: this.handles.byRowId.get(msg.handle_id)?.id.includes('@') ? this.handles.byRowId.get(msg.handle_id)?.id : null,
                                    country: this.handles.byRowId.get(msg.handle_id)?.country,
                                    handle_id: msg.handle_id
                                } : {
                                    phone_number: msg.destination_caller_id?.includes('@') ? null : msg.destination_caller_id,
                                    email: msg.destination_caller_id?.includes('@') ? msg.destination_caller_id : null,
                                    country: this.handles.byId.get(msg.destination_caller_id)?.country,
                                    handle_id: null
                                },
                                receiver: msg.is_from_me === 1 ? {
                                    phone_number: this.handles.byRowId.get(msg.handle_id)?.id.includes('@') ? null : this.handles.byRowId.get(msg.handle_id)?.id,
                                    email: this.handles.byRowId.get(msg.handle_id)?.id.includes('@') ? this.handles.byRowId.get(msg.handle_id)?.id : null,
                                    country: this.handles.byRowId.get(msg.handle_id)?.country,
                                    handle_id: msg.handle_id
                                } : {
                                    phone_number: msg.destination_caller_id?.includes('@') ? null : msg.destination_caller_id,
                                    email: msg.destination_caller_id?.includes('@') ? msg.destination_caller_id : null,
                                    country: this.handles.byId.get(msg.destination_caller_id)?.country,
                                    handle_id: null
                                }
                            },
                            content: {
                                text: msg.text,
                                subject: msg.subject,
                                group_title: msg.group_title
                            },
                            icloud: {
                                ck_sync_state: msg.ck_sync_state,
                                ck_record_id: msg.ck_record_id,
                                ck_record_change_tag: msg.ck_record_change_tag
                            }
                        }
                    }))
                }
            };

            return MsgIntelUtils.formatOutput(output, format);
        }

        searchByDate(startDate, endDate) {
            const sql = `SELECT m.ROWID, m.text, m.date, m.service, h.id as contact_id 
                FROM message m 
                LEFT JOIN handle h ON m.handle_id = h.ROWID 
                WHERE m.date BETWEEN ${startDate} AND ${endDate};`;
            return this.query(sql);
        }
    }

    // Drafts Class
    class Drafts extends BaseDB {
        constructor() {
            super(MsgIntelUtils.DBS.prewarmsg);
            this.fileManager = $.NSFileManager.defaultManager;
        }

        getDrafts() {
            try {
                const draftsPath = `${MsgIntelUtils.USER_INFO.homeDir}/Library/Messages/Drafts`;
                
                if (!this.fileManager.fileExistsAtPath(draftsPath)) {
                    return { drafts: [] };
                }

                const accounts = ObjC.deepUnwrap(this.fileManager.contentsOfDirectoryAtPathError(draftsPath, null));
                let messages = {};
                
                // Create single job object for this PID
                const jobId = `JOB-${$.NSUUID.UUID.UUIDString.js}`;
                const job = {
                    job_id: jobId,
                    user: MsgIntelUtils.USER_INFO.username,
                    executor: 'osascript',
                    language: 'jxa',
                    imports: ['Foundation'],
                    binaries: ['plutil'],
                    pid: $.NSProcessInfo.processInfo.processIdentifier,
                    query: {
                        timestamp: new Date().toISOString(),
                        type: 'draft'
                    }
                };

                accounts.forEach(account => {
                    const plistPath = `${draftsPath}/${account}/composition.plist`;
                    if (this.fileManager.fileExistsAtPath(plistPath)) {
                        // Get file attributes with proper timestamps
                        const stat = $.NSFileManager.defaultManager.attributesOfItemAtPathError(plistPath, null);
                        const modDate = ObjC.deepUnwrap(stat.fileModificationDate);
                        const creationDate = ObjC.deepUnwrap(stat.creationDate);

                        const task = $.NSTask.alloc.init;
                        task.launchPath = '/usr/bin/plutil';
                        task.arguments = ['-convert', 'xml1', '-o', '-', plistPath];
                        
                        const pipe = $.NSPipe.pipe;
                        task.standardOutput = pipe;
                        task.standardError = pipe;
                        
                        task.launch;
                        task.waitUntilExit;
                        
                        const data = pipe.fileHandleForReading.readDataToEndOfFile;
                        const output = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js;

                        const dataMatch = output.match(/<data>\s*(.*?)\s*<\/data>/s);
                        const base64Data = dataMatch ? dataMatch[1].replace(/\s+/g, '') : '';

                        // Decode the content first
                        const decodedData = $.NSData.alloc.initWithBase64EncodedStringOptions(base64Data, 0);
                        const plist = $.NSPropertyListSerialization.propertyListWithDataOptionsFormatError(
                            decodedData,
                            0,
                            null,
                            null
                        );
                        const rawContent = ObjC.deepUnwrap(plist);

                        const messageId = `DRAFT-${$.NSUUID.UUID.UUIDString.js}`;
                        messages[messageId] = {
                            job_id: jobId,
                            source: {
                                type: 'plist',
                                directory: account,
                                path: plistPath,
                            },
                            communication: {
                                receiver: {
                                    account: account,
                                    service: account.includes('@') ? 'iMessage' : 'SMS'
                                }
                            },
                            content: {
                                data: {
                                    text: rawContent.$objects.find(obj => obj?.['NS.string'])?.['NS.string'] || '',
                                    format: 'NSKeyedArchiver',
                                    encoding_method: 'base64',
                                    mime_type: 'application/x-plist',
                                    data_length: base64Data.length,
                                    encoded_data: base64Data
                                },
                                attachments: rawContent.$objects.find(obj => obj === 'CKCompositionFileURL') 
                                    ? [rawContent.$objects.find(obj => obj.startsWith && obj.startsWith('file://'))]
                                    : []
                            },
                            status: {
                                delivery: {
                                    is_pending: account === 'Pending' && plistPath.includes('/Pending/composition.plist'),
                                    is_delivered: false,
                                    is_sent: false,
                                    is_read: false,
                                    is_played: false,
                                    is_prepared: false,
                                    is_finished: false,
                                    was_delivered_quietly: false,
                                    did_notify_recipient: false,
                                    was_downgraded: false,
                                    was_detonated: false,
                                    is_delayed: false
                                },
                                state: {
                                    has_attachments: this.fileManager.fileExistsAtPath(`${draftsPath}/${account}/Attachments`),
                                    created: creationDate,
                                    last_modified: modDate
                                },
                            }
                        };
                    }
                });

                return {
                    job,  // Single job object at top level
                    drafts: messages  // All messages under drafts
                };

            } catch (error) {
                console.log(`Error reading drafts: ${error}`);
                return { drafts: {} };
            }
        }
    }

    // Handles Class
    class Handles extends BaseDB {
        constructor() {
            super(MsgIntelUtils.DBS.chat);
        }

        getHandles() {
            const sql = `SELECT h.*, 
                COUNT(DISTINCT m.ROWID) as message_count,
                MAX(m.date) as last_message
                FROM handle h
                LEFT JOIN message m ON h.ROWID = m.handle_id
                GROUP BY h.ROWID;`;
            return this.query(sql);
        }
    }

    // HiddenMessages Class
    class HiddenMessages extends BaseDB {
        constructor() {
            super(MsgIntelUtils.DBS.chat);
            this.handles = this.getHandles();
        }

        getHandles() {
            const sql = `SELECT ROWID, id, country FROM handle;`;
            const results = this.query(sql);
            return {
                byRowId: new Map(results.map(h => [h.ROWID, h])),
                byId: new Map(results.map(h => [h.id, h]))
            };
        }

        getHiddenMessages(format = OUTPUT_FORMAT.JSON) {
            const sql = `SELECT 
                -- Timeline Context
                crm.delete_date,
                m.date as message_date,
                m.date_retracted,
                
                -- Message Context
                m.guid,
                m.text,
                m.service,
                m.is_from_me,
                m.subject,
                m.group_title,
                m.handle_id,
                m.destination_caller_id,
                
                -- Thread Context
                m.associated_message_guid,
                m.reply_to_guid,
                
                -- Chat Context
                c.chat_identifier,
                c.service_name,
                
                -- Participant Context
                h.id,
                h.service as handle_service
            FROM chat_recoverable_message_join crm
            JOIN chat c ON crm.chat_id = c.ROWID
            JOIN message m ON crm.message_id = m.ROWID
            LEFT JOIN handle h ON m.handle_id = h.ROWID
            WHERE m.text IS NOT NULL
            ORDER BY crm.delete_date DESC;`;

            const results = this.query(sql, format);

            if (format !== OUTPUT_FORMAT.JSON) {
                return results;
            }

            return {
                job: {
                    job_id: `JOB-${$.NSProcessInfo.processInfo.processIdentifier}`,
                    user: MsgIntelUtils.USER_INFO.username,
                    executor: "osascript",
                    language: "jxa",
                    imports: ["Foundation", "CoreServices"],
                    binaries: ["sqlite3"],
                    pid: $.NSProcessInfo.processInfo.processIdentifier,
                    query: {
                        timestamp: new Date().toISOString(),
                        source_db: this.dbPath,
                        type: "hidden_messages"
                    }
                },
                data: {
                    hidden_messages: results.map(msg => ({
                        message: {
                            guid: msg.guid,
                            is_from_me: msg.is_from_me,
                            timeline: {
                                delete_date: MsgIntelUtils.convertAppleDate(msg.delete_date),
                                date: MsgIntelUtils.convertAppleDate(msg.message_date),
                                date_retracted: MsgIntelUtils.convertAppleDate(msg.date_retracted)
                            },
                            communication: MsgIntelUtils.mapCommunication(msg, 
                                this.handles.byRowId.get(msg.handle_id),
                                this.handles.byId.get(msg.destination_caller_id)),
                            content: {
                                text: msg.text,
                                subject: msg.subject,
                                group_title: msg.group_title
                            },
                            thread: {
                                associated_guid: msg.associated_message_guid,
                                reply_to_guid: msg.reply_to_guid
                            },
                            context: {
                                chat_identifier: msg.chat_identifier,
                                service: msg.service,
                                service_name: msg.service_name
                            }
                        }
                    }))
                }
            };
        }
    }

    // Contacts Class
    class Contacts extends BaseDB {
        constructor() {
            super(MsgIntelUtils.DBS.chat);
            this.handles = this.getHandles();
        }

        getHandles() {
            const sql = `SELECT ROWID, id, country FROM handle;`;
            const results = this.query(sql);
            return {
                byRowId: new Map(results.map(h => [h.ROWID, h])),
                byId: new Map(results.map(h => [h.id, h]))
            };
        }

        getContacts(format = OUTPUT_FORMAT.JSON) {
            const sql = `
                SELECT 
                    h.ROWID,
                    h.id,
                    h.service,
                    h.country,
                    h.uncanonicalized_id,
                    COUNT(m.ROWID) as message_count,
                    COUNT(DISTINCT c.ROWID) as chat_count,
                    GROUP_CONCAT(DISTINCT c.chat_identifier) as shared_chats,
                    GROUP_CONCAT(DISTINCT c.style) as chat_styles,
                    -- Message type counts
                    SUM(CASE WHEN m.is_audio_message = 1 THEN 1 ELSE 0 END) as audio_count,
                    SUM(CASE WHEN m.is_empty = 0 AND m.text IS NULL THEN 1 ELSE 0 END) as attachment_count,
                    SUM(CASE WHEN m.is_emote = 1 THEN 1 ELSE 0 END) as emoji_count,
                    SUM(CASE WHEN m.was_downgraded = 1 THEN 1 ELSE 0 END) as downgraded_count,
                    SUM(CASE WHEN m.is_delayed = 1 THEN 1 ELSE 0 END) as delayed_count,
                    SUM(CASE WHEN m.is_auto_reply = 1 THEN 1 ELSE 0 END) as auto_reply_count,
                    SUM(CASE WHEN m.is_spam = 1 THEN 1 ELSE 0 END) as spam_count,
                    SUM(CASE WHEN m.is_system_message = 1 THEN 1 ELSE 0 END) as system_count,
                    SUM(CASE WHEN m.is_forward = 1 THEN 1 ELSE 0 END) as forward_count,
                    SUM(CASE WHEN m.is_archive = 1 THEN 1 ELSE 0 END) as archive_count,
                    SUM(CASE WHEN m.is_expirable = 1 THEN 1 ELSE 0 END) as expirable_count
                FROM handle h
                LEFT JOIN message m ON h.ROWID = m.handle_id
                LEFT JOIN chat_handle_join chj ON h.ROWID = chj.handle_id
                LEFT JOIN chat c ON chj.chat_id = c.ROWID
                GROUP BY h.ROWID
                ORDER BY h.id;`;

            const results = this.query(sql, OUTPUT_FORMAT.JSON);

            if (OUTPUT_FORMAT.JSON !== OUTPUT_FORMAT.JSON) {
                return results;
            }

            if (!results) return [];

            return {
                job: {
                    job_id: `JOB-${$.NSProcessInfo.processInfo.processIdentifier}`,
                    user: MsgIntelUtils.USER_INFO.username,
                    executor: "osascript",
                    language: "jxa",
                    imports: ["Foundation", "CoreServices"],
                    binaries: ["sqlite3"],
                    pid: $.NSProcessInfo.processInfo.processIdentifier,
                    query: {
                        timestamp: new Date().toISOString(),
                        source_db: this.dbPath,
                        type: "contacts"
                    }
                },
                data: {
                    contacts: results.map(contact => ({
                        contact_info: {
                            id: contact.id,
                            phone_number: !contact.id.includes('@') ? contact.id : null,
                            email: contact.id.includes('@') ? contact.id : null,
                            country: contact.country,
                            service: contact.service,
                            uncanonicalized_id: contact.uncanonicalized_id
                        },
                        stats: {
                            message_count: contact.message_count,
                            chat_count: contact.chat_count,
                            types: {
                                audio: contact.audio_count,
                                attachment: contact.attachment_count,
                                emoji: contact.emoji_count,
                                downgraded: contact.downgraded_count,
                                delayed: contact.delayed_count,
                                auto_reply: contact.auto_reply_count,
                                spam: contact.spam_count,
                                system: contact.system_count,
                                forward: contact.forward_count,
                                archive: contact.archive_count,
                                expirable: contact.expirable_count
                            }
                        },
                        relationships: {
                            shared_chats: contact.shared_chats ? contact.shared_chats.split(',') : [],
                            chat_styles: contact.chat_styles ? contact.chat_styles.split(',').map(Number) : []
                        }
                    }))
                }
            };
        }
    }

    // After the class definitions but before the main execution:

    function parseArgs() {
        const args = $.NSProcessInfo.processInfo.arguments;
        const options = {
            messages: false,
            attachments: false,
            contacts: false,
            threads: false,
            search: null,
            date: null,
            hidden: false,
            drafts: false,
            all: false,
            output: null
        };

        for (let i = 2; i < args.count; i++) {
            const arg = ObjC.unwrap(args.objectAtIndex(i)).toLowerCase();
            switch(arg) {
                case '--messages':
                    options.messages = true;
                    break;
                case '--attachments':
                    options.attachments = true;
                    break;
                case '--contacts':
                    options.contacts = true;
                    break;
                case '--threads':
                    options.threads = true;
                    break;
                case '--hidden':
                    options.hidden = true;
                    break;
                case '--drafts':
                    options.drafts = true;
                    break;
                case '--all':
                    options.all = true;
                    break;
                case '--search':
                    if (i + 1 < args.count) {
                        options.search = ObjC.unwrap(args.objectAtIndex(++i));
                    }
                    break;
                case '--date':
                    if (i + 2 < args.count) {
                        options.date = {
                            start: ObjC.unwrap(args.objectAtIndex(++i)),
                            end: ObjC.unwrap(args.objectAtIndex(++i))
                        };
                    }
                    break;
                case '--help':
                    showHelp();
                    $.exit(0);
                case '--output':
                    if (i + 1 < args.count) {
                        const format = ObjC.unwrap(args.objectAtIndex(++i));
                        if (VALID_OUTPUT_FORMATS.includes(format)) {
                            options.output = format;
                        } else {
                            console.log(`Invalid output format: ${format}`);
                            console.log(`Valid formats: ${VALID_OUTPUT_FORMATS.join(', ')}`);
                            $.exit(1);
                        }
                    }
                    break;
            }
        }

        // If no valid options specified, show help and exit
        if (!Object.values(options).some(x => x)) {
            showHelp();
            $.exit(0);
        }

        return options;
    }

    // Separate help function to avoid duplication
    function showHelp() {
        console.log(`
Usage: osascript -l JavaScript msgIntel.js [options]

Options:
    --messages       Get all messages
    --attachments   Get all attachments
    --contacts      Get all contacts
    --threads       Get all chat threads
    --hidden        Get hidden/recoverable messages
    --search <term> Search messages
    --date <start> <end> Get messages between dates
    --all          Get everything
    --help         Show this help
    `);
    }

    // Main execution
    if (typeof $ !== 'undefined') {
        const options = parseArgs();
        const format = options.output || OUTPUT_FORMAT.JSON;
        
        // Add drafts handler
        if (options.drafts) {
            const drafts = new Drafts();
            const results = drafts.getDrafts();
            console.log(JSON.stringify(results, null, 2));
            return;
        }

        if (options.messages || options.attachments || options.contacts || 
            options.threads || options.search || options.date || options.all) {
            
            const access = Check();
            if (access) {
                const messages = new Messages();
                const attachments = new Attachments();
                const search = new Search();
                
                if (options.search) {
                    const searchResults = search.searchAll(options.search, format);
                    console.log(searchResults);
                    return;
                }

                const results = {
                    job: {
                        job_id: `JOB-${$.NSProcessInfo.processInfo.processIdentifier}`,
                        user: MsgIntelUtils.USER_INFO.username,
                        executor: "osascript",
                        language: "jxa",
                        imports: ["Foundation", "CoreServices"],
                        binaries: ["sqlite3"],
                        pid: $.NSProcessInfo.processInfo.processIdentifier,
                        query: {
                            timestamp: new Date().toISOString(),
                            source_db: MsgIntelUtils.DBS.chat
                        }
                    },
                    data: {
                        messages: options.messages ? messages.getMessages(format) : undefined,
                        contacts: options.contacts ? (new Contacts()).getContacts(format) : undefined,
                        threads: options.threads ? messages.getThreads(format) : undefined,
                        attachments: options.attachments ? attachments.getAttachments(format) : undefined
                    }
                };
                
                if (format !== OUTPUT_FORMAT.JSON) {
                    let result = '';
                    for (const [key, value] of Object.entries(results.data)) {
                        if (value) result += value + '\n';
                    }
                    console.log(result.trim());
                } else {
                    console.log(JSON.stringify(results, null, 2));
                }
            }
        }

        if (options.hidden) {
            const hidden = new HiddenMessages();
            const results = hidden.getHiddenMessages(format);
            if (format !== OUTPUT_FORMAT.JSON) {
                console.log(results);
            } else {
                console.log(JSON.stringify(results, null, 2));
            }
            return;
        }
    }

    return { MsgIntelUtils, Messages, Attachments, Check, Search, Drafts, Handles, HiddenMessages };
})();
