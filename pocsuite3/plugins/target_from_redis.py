from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import register_plugin


class TargetFromRedis(PluginBase):
    category = PLUGIN_TYPE.TARGETS

    @staticmethod
    def get_redis(redis_url=None):
        ret = None
        try:
            import os
            from redis import Redis

            if redis_url is None:
                if 'REDIS_URL' in os.environ:
                    redis_url = os.environ.get('REDIS_URL', 'redis://@localhost:6379/0')
                else:
                    redis_url = 'redis://@localhost:6379/0'

            redis = Redis.from_url(redis_url)
            redis.ping()
            ret = redis

        except ImportError:
            error_msg = 'try "pip install redis" first!'
            logger.error(error_msg)
            raise

        except Exception as ex:
            logger.error(str(ex))
            raise

        return ret

    def init(self):
        r = self.get_redis()
        if r:
            key = 'pocsuite_target'
            info_msg = "[PLUGIN] try fetch targets from redis..."
            logger.info(info_msg)

            targets = r.get(key)
            count = 0
            if targets:
                for target in targets:
                    if self.add_target(target):
                        count += 1

            info_msg = "[PLUGIN] get {0} target(s) from redis".format(count)
            logger.info(info_msg)


register_plugin(TargetFromRedis)
