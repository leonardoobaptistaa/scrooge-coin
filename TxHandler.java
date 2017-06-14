import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
public class TxHandler {

    private UTXOPool pool;
    private double totalInputSum;
    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.pool = new UTXOPool(utxoPool);
        this.totalInputSum = 0;
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        this.totalInputSum = 0;
        return validateRuleNumber12And3(tx) &&
               validateRuleNumber4And5(tx);
    }

    private boolean validateRuleNumber12And3(Transaction tx) {
        HashMap<UTXO, Boolean> usedUTXO = new HashMap<UTXO, Boolean>();

        for (int i = 0;  i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            if (input == null) { return false; }

            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            //rule number 1
            if (this.pool.contains(utxo) == false) {
              return false;
            }

            Transaction.Output previousTxOutput = this.pool.getTxOutput(utxo);
            if (previousTxOutput == null) { return false; }

            PublicKey publicKey = previousTxOutput.address;
            byte[] message = tx.getRawDataToSign(i);
            byte[] signature = input.signature;
            //rule number 2
            if (Crypto.verifySignature(publicKey, message, signature) == false) {
              return false;
            }

            //rule number 3
            if (usedUTXO.containsKey(utxo)) { return false; }

            usedUTXO.put(utxo, true);

            //saving this value for rule number 5
            this.totalInputSum += previousTxOutput.value;
        }

        return true;
    }

    private boolean validateRuleNumber4And5(Transaction tx) {
        double outputSum = 0;

        for (int i = 0;  i < tx.numOutputs(); i++) {
            Transaction.Output output = tx.getOutput(i);
            if (output == null) { return false; }
            if (output.value < 0) { return false; }

            outputSum += output.value;
        }

        return this.totalInputSum >= outputSum;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        if (possibleTxs == null) {
            return new Transaction[0];
        }

        ArrayList<Transaction> validTxs = new ArrayList<>();

        for (Transaction tx : possibleTxs) {
            if (!isValidTx(tx)) {
                continue;
            }
            validTxs.add(tx);

            for (Transaction.Input input : tx.getInputs()) {
                UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                this.pool.removeUTXO(utxo);
            }
            byte[] txHash = tx.getHash();
            int index = 0;
            for (Transaction.Output output : tx.getOutputs()) {
                UTXO utxo = new UTXO(txHash, index);
                index += 1;
                this.pool.addUTXO(utxo, output);
            }
        }

        return validTxs.toArray(new Transaction[validTxs.size()]);
    }

}
