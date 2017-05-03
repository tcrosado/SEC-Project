package pt.ulisboa.tecnico.sec.tg11;

import java.sql.Timestamp;

/**
 * Created by trosado on 5/3/17.
 */
public class ServerResult {

    private Integer serverId;
    private Timestamp creationTime;
    private byte[] message;

    public ServerResult() {
        this.serverId = -1;
        this.creationTime = null;
        this.message = new byte[0];
    }

    public Integer getServerId() {
        return serverId;
    }

    public void setServerId(Integer serverId) {
        this.serverId = serverId;
    }

    public Timestamp getCreationTime() {
        return creationTime;
    }

    public void setCreationTime(Timestamp creationTime) {
        this.creationTime = creationTime;
    }

    public byte[] getMessage() {
        return message;
    }

    public void setMessage(byte[] message) {
        this.message = message;
    }
}
