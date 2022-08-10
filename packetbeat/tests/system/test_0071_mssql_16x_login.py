from packetbeat import BaseTest


class Test(BaseTest):

    def test_mssql_16x_login(self):
        self.render_config_template(
            mssql_ports=[1433]
        )
        self.run_packetbeat(pcap="mssql_login.pcap",
                            debug_selectors=["mssql,tcp,publish"])

        objs = self.read_output()
        assert all([o["server.port"] == 1433 for o in objs])

        assert len(objs) == 3
        assert objs[0]["status"] == "OK"
        assert objs[0]["mssql.version"] == 16
        assert objs[0]["mssql.db_name"] == "master"

        assert objs[1]["method"] == "SET"
        assert objs[2]["method"] == "SET"

