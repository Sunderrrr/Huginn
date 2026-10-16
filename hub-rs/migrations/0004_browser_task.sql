-- New task type: browser automation. The payload carries an ordered list of
-- steps (navigate/click/type/eval/screenshot/get_text/get_html/wait_for) that
-- a Linux worker executes by driving a local Obscura headless-browser process
-- over CDP. Windows workers answer "browser not supported on this OS".
ALTER TYPE public.task_type ADD VALUE IF NOT EXISTS 'browser';
