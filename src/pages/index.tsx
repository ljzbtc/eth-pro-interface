import { ConnectButton } from '@rainbow-me/rainbowkit';
import type { NextPage } from 'next';
import WalletGenerator from '../components/WalletGenerator';
import styles from '../styles/Home.module.css';

const Home: NextPage = () => {
  return (
    <div>
      <WalletGenerator />
      <div className={styles.container}>
        <ConnectButton /> 
    </div>
    </div>

  );
};

export default Home;
