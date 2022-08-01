package com.paycorp.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class App {
    private static final Logger LOGGER = LoggerFactory.getLogger(App.class);

    private static class Handler {

        public enum Operation {
            ENCRYPT,
            DECRYPT,
            VERIFY,
            SIGN,
            SIGN_ENCRYPT,
            DECRYPT_VERIFY,
            NO_OPERATION
        }

        Operation oper;
        String inputFile;
        String outputFile;
        // TODO:Need to remove hardcoded values
        String key = "b5ff6db1e2f1d27d294047b220516312da1b4ba899035692e893e16815fc9784";

        private static final Encryption enc = new Encryption();
        private static final XMLSignVerify svXML = new XMLSignVerify();

        public Handler(Handler.Operation oper, String inputFile, String outputFile) {
            this.oper = oper;
            this.inputFile = inputFile;
            this.outputFile = outputFile;

        }

        public boolean execute() throws IOException, Exception {

            if (oper == Operation.NO_OPERATION)
                return false;
            if (oper == Operation.DECRYPT_VERIFY) {
                String plain = enc.decrypt(
                        Files.readString(Paths.get(inputFile),
                                StandardCharsets.UTF_8),
                        key);
                boolean verify = svXML.verifyXML(plain);
                Files.writeString(Paths.get(outputFile), plain);
                return verify;
            }
            if (oper == Operation.SIGN_ENCRYPT) {

                String signXML = svXML.signXML(Files.readString(Paths.get(inputFile)));
                String encrypt = enc.encrypt(signXML, key);
                Files.writeString(Paths.get(outputFile), encrypt);
                return true;
            }
            if (oper == Operation.DECRYPT) {
                String plain = enc.decrypt(
                        Files.readString(Paths.get(inputFile),
                                StandardCharsets.UTF_8),
                        key);
                Files.writeString(Paths.get(outputFile), plain);
                return true;

            }
            if (oper == Operation.ENCRYPT) {
                String encrypt = enc.encrypt(Files.readString(Paths.get(inputFile)), key);
                Files.writeString(Paths.get(outputFile), encrypt);
            }
            if (oper == Operation.VERIFY) {
                boolean verify = svXML.verifyXML(Files.readString(Paths.get(inputFile)));
                return verify;
            }
            if (oper == Operation.SIGN) {
                String signXML = svXML.signXML(Files.readString(Paths.get(inputFile)));
                Files.writeString(Paths.get(outputFile), signXML);
                return true;
            }
            return true;
        }
    }

    public static void main(String[] args) {
        LOGGER.info("WELCOME TO PAYCORP DIGITAL SIGNING MODULE");
        try {
            Handler handler = parseArgument(args);
            handler.execute();

        } catch (Exception e) {
            LOGGER.error("Exception raised ", e);
        }

    }

    public static Handler parseArgument(String[] args) {

        Options options = new Options();
        

        try {

            setOptions(options);
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.getArgs().length != 0) {
                printDefault("Unrecognized Parameter", options);
            } else if (cmd.hasOption("h")) {
                printDefault("Help Requested", options);
            } else if (cmd.hasOption("e") && cmd.hasOption("s")) {
                LOGGER.info("File to be Encrypted and Signed");
                return new Handler(
                        Handler.Operation.SIGN_ENCRYPT,
                        cmd.getOptionValue("i"),
                        cmd.getOptionValue("o"));
            } else if (cmd.hasOption("d") && cmd.hasOption("v")) {
                LOGGER.info("File to be Decrypted and Verified");

                return new Handler(
                        Handler.Operation.DECRYPT_VERIFY,
                        cmd.getOptionValue("i"),
                        cmd.getOptionValue("o"));
            } else if (cmd.hasOption("e")) {
                LOGGER.info("File to be Encrypted");
                return new Handler(
                        Handler.Operation.ENCRYPT,
                        cmd.getOptionValue("i"),
                        cmd.getOptionValue("o"));
            }
            if (cmd.hasOption("d")) {
                LOGGER.info("File to be Decrypted");
                return new Handler(
                        Handler.Operation.DECRYPT,
                        cmd.getOptionValue("i"),
                        cmd.getOptionValue("o"));
            }
            if (cmd.hasOption("v")) {
                LOGGER.info("File to be Verified");
                return new Handler(
                        Handler.Operation.VERIFY,
                        cmd.getOptionValue("i"),
                        cmd.getOptionValue("o"));
            }
            if (cmd.hasOption("s")) {
                LOGGER.info("File to be Signed");
                return new Handler(
                        Handler.Operation.SIGN,
                        cmd.getOptionValue("i"),
                        cmd.getOptionValue("o"));
            } else {
                printDefault("Invalid Option", options);
            }

        } catch (ParseException pe) {
            printDefault("Invalid Option", options, pe);
        }
        return new Handler(Handler.Operation.NO_OPERATION, "", "");
    }

    private static void setOptions(Options options) {
        options.addOption(Option.builder("h")
                .longOpt("help")
                .hasArg(false)
                .desc("Help on this tool usage")
                .required(false)
                .build());

        options.addOption(Option.builder("e")
                .longOpt("encrypt")
                .hasArg(false)
                .desc("Encrypt the input file")
                .required(false)
                .build());

        options.addOption(Option.builder("d")
                .longOpt("decrypt")
                .hasArg(false)
                .desc("Decrypt the input file")
                .required(false)
                .build());

        options.addOption(Option.builder("s")
                .longOpt("sign")
                .hasArg(false)
                .desc("Sign the XML File")
                .required(false)
                .build());

        options.addOption(Option.builder("v")
                .longOpt("verify")
                .hasArg(false)
                .desc("Verify the signature of XML File")
                .required(false)
                .build());

        options.addOption(Option.builder("i")
                .longOpt("inputFile")
                .hasArg(true)
                .desc("Input File")
                .required(true)
                .build());

        options.addOption(Option.builder("o")
                .longOpt("outputFile")
                .hasArg(true)
                .desc("Output File")
                .required(true)
                .build());

    }

    private static void printDefault(String message, Options options, ParseException pe) {
        LOGGER.info(message);
        LOGGER.info(pe.getMessage());
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("security.sh", options);
    }

    private static void printDefault(String message, Options options) {
        LOGGER.info(message);
        HelpFormatter formatter = new HelpFormatter();
        formatter.setOptionComparator(null);
        formatter.printHelp("security.sh", options);
    }

}
