const axios = require('axios');
const {SocksProxyAgent} = require('socks-proxy-agent');

const agent = new SocksProxyAgent('socks5h://127.0.0.1:9050'); // Tor SOCKS5 proxy

const blockcypherUrl = 'https://api.blockcypher.com/v1/btc/test3/addrs';

async function getTransactions(address) {
    try {
        console.log(`Fetching transactions for address: ${address}`);

        const response = await axios.get(`${blockcypherUrl}/${address}/full`, {
            httpsAgent: agent,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        });

        if (response.status === 200) {
            console.log('Transaction data:', response.data);
            return response.data;
        } else {
            console.error('Received non-200 status:', response.status);
            return [];
        }
    } catch (error) {
        console.error('Error occurred:', error.message);
        return [];
    }
}

(async () => {
    const address = "tb1p9qsz6jcehlk30k0hl9fgujcyx0ym0quehwhcr2jd732far44ylmqhsygmw";
    const results = await getTransactions(address);
    console.log(results);
})();

