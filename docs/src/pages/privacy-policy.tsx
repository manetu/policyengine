import React, {useEffect, useState} from 'react';
import Layout from '@theme/Layout';
import useIsBrowser from '@docusaurus/useIsBrowser';

const POLICY_ID = '26730545';
const PROD_URL = `https://www.iubenda.com/api/privacy-policy/${POLICY_ID}/no-markup`;
const DEV_URL = `/api/iubenda/privacy-policy/${POLICY_ID}/no-markup`;

export default function PrivacyPolicy(): React.JSX.Element {
  const isBrowser = useIsBrowser();
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isBrowser) return;

    const isDev = window.location.hostname === 'localhost';
    const apiUrl = isDev ? DEV_URL : PROD_URL;

    fetch(apiUrl)
      .then((response) => {
        if (!response.ok) {
          throw new Error('Failed to load privacy policy');
        }
        return response.json();
      })
      .then((data) => {
        setContent(data.content);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [isBrowser]);

  return (
    <Layout title="Privacy Policy" description="Privacy Policy for Manetu PolicyEngine">
      <main style={{padding: '2rem', maxWidth: '1200px', margin: '0 auto'}}>
        {loading && <p>Loading privacy policy...</p>}
        {error && <p>Error: {error}</p>}
        {content && (
          <div id="policy-html" dangerouslySetInnerHTML={{__html: content}} />
        )}
      </main>
    </Layout>
  );
}
