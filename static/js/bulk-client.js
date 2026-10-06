/* Keep each serverless request bounded while allowing ten links in the original UI. */
'use strict';
async function scanBulkBatches(urls, batchSize, submit, onProgress = () => {}) {
    if (!Array.isArray(urls) || !urls.length || urls.length > 10 || !urls.every(url => typeof url === 'string')) {
        throw new Error('Enter between one and ten URL strings.');
    }
    const size = Number.isInteger(batchSize) && batchSize >= 1 && batchSize <= 10 ? batchSize : 2;
    const aggregate = {results:[], errors:[], total_scanned:0, successful_scans:0, failed_scans:0,
        cached_results:0, new_scans:0, suspicious_count:0, safe_count:0, partial_count:0};
    const counters = ['cached_results','new_scans','suspicious_count','safe_count','partial_count'];
    for (let offset = 0; offset < urls.length; offset += size) {
        const batch = urls.slice(offset, offset + size);
        let data;
        try {
            data = await submit(batch);
            if (!data || !Array.isArray(data.results) || !Array.isArray(data.errors)
                || data.results.length + data.errors.length !== batch.length
                || counters.some(key => !Number.isInteger(data[key]) || data[key] < 0)) {
                throw new Error('Server returned incomplete bulk results. No verdict was inferred.');
            }
        } catch (error) {
            // Keep completed evidence. A failed request has no authoritative scan result;
            // stop here rather than retrying unknown work or exhausting provider quotas.
            aggregate.errors.push(...batch.map(url => ({url, error:error.message || 'Bulk request failed.', code:'request_failed'})));
            aggregate.errors.push(...urls.slice(offset + size).map(url => ({url, error:'Not scanned because an earlier batch request failed. Please retry this URL.', code:'not_scanned'})));
            break;
        }
        aggregate.results.push(...data.results);
        aggregate.errors.push(...data.errors);
        for (const key of counters) aggregate[key] += data[key];
        aggregate.total_scanned = offset + batch.length;
        aggregate.successful_scans = aggregate.results.length;
        aggregate.failed_scans = aggregate.errors.length;
        onProgress(aggregate.total_scanned, urls.length, Math.floor(offset / size) + 1, aggregate);
    }
    aggregate.total_scanned = urls.length;
    aggregate.successful_scans = aggregate.results.length;
    aggregate.failed_scans = aggregate.errors.length;
    return aggregate;
}
